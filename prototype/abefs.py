# Version 0.3

from __future__ import print_function
import os, sys, errno, json
from fuse import FUSE, FuseOSError, Operations, fuse_get_context
from crypto import ABECrypto
from pwd import getpwuid
from json import dumps, loads
from math import ceil

DEBUG = True

# FUSE class.
class ABEFS(Operations):
    def __init__(self, root):
        self.root = root
        self._abe = ABECrypto()
        self._user_cache = {}
        self._file_cache = {}

        # Open default policy file.
        try:
            printDebug("__init__", "opening {}".format(root + "/.policy"))
            policy_file = open(root + "/.policy")
        except IOError:
            print("No policy file detected. Create a policy file in '" + root + "'",
                  file = sys.stderr)
            sys.exit(1)

        self._policy = policy_file.read()

    # Creates a path relative to the specified root.
    def _full_path(self, path):
        if path.startswith("/"):
            path = path[1:]

        path = os.path.join(self.root, path)
        return path

    # Finds the user's username.
    def _getusername(self):
        return getpwuid(os.getuid())[0]

    # Automatically generates a list of attributes and a secret key for a user.
    # FIXME: Attributes should be specified externally from the filesystem.
    def _generate_user_attr(self):
        uid, gid, pid = fuse_get_context()
        attr_list = ["UID" + str(uid), "GID" + str(gid)]
        self._user_cache[uid] = {"attr": attr_list, 
                                  "key": self._abe.get_secret_key(attr_list)}

    # Read the first block of a file to get its ABE metatdata.
    def _read_metadata(self, fd):
        os.lseek(fd, 0, os.SEEK_SET)

        # Read length of CP-ABE header.
        abe_header_len = int.from_bytes(os.read(fd, 8), byteorder = "big")
        printDebug("_read_metadata", "header length: {}".format(abe_header_len))

        # Read CP-ABE header data.
        raw_bytes = self._unpad(os.read(fd, abe_header_len))
        printDebug("_read_metadata", "length of raw c1: {}".format(len(raw_bytes)))
        c1 = self._abe.fromBytes(raw_bytes)

        # Read IV data.
        raw_bytes = self._unpad(os.read(fd, 4096))
        IVs = []
        for i in range(0, len(raw_bytes), 16):
            IVs.append(raw_bytes[i: i + 16])
        printDebug("_read_metadata", "IVs {}".format(IVs))
        iv_len = len(IVs)
        IVs += [b"\x00" * 16] * (256 - iv_len % 256)
        printDebug("_read_metadata", "IV len {}".format(len(IVs)))

        # Read tag data.
        raw_bytes = self._unpad(os.read(fd, 4096))
        MACs = []
        for i in range(0, len(raw_bytes), 16):
            MACs.append(raw_bytes[i: i + 16])
        printDebug("_read_metadata", "tags {}".format(MACs))
        tag_len = len(MACs)
        MACs += [b"\x00" * 16] * (256 - tag_len % 256)
        printDebug("_read_metadata", "tag len {}".format(len(MACs)))

        return {"c1": c1, "IV": IVs, "tags": MACs, "header_len": abe_header_len}

    # Writes metadata to a file.
    def _write_metadata(self, fd):
        pass

    # Padding based on ANSIX923 and PKCS7.
    def _pad(self, obj):
        size = len(obj)
        printDebug("_pad", "size of obj: {}".format(size))

        if size % 4096:
            pad_len = 4096 - (size % 4096)
            printDebug("_pad", "pad_len: {}".format(pad_len))

            # Do ANSIX923 like padding but using the last two bytes to store the size.
            if pad_len > 2:
                pad = bytes(4096 - (size % 4096) - 2)
                pad += len(pad).to_bytes(2, byteorder = "big")
                assert(len(pad) + size == 4096)
            # Otherwise, do a PKCS7 like padding with the last one or two bytes.
            elif pad_len == 2:
                pad = b"\x02\x02"
            else:
                pad = b"\x01"

            return obj + pad
        # If a full block in length, don't pad.
        else:
            return obj

    def _unpad(self, obj):
        # Attempt to detect our ANSIX923 like padding.
        pad_len = int.from_bytes(obj[-2:], byteorder = "big")
        printDebug("_unpad", "pad_len: {}".format(pad_len))
        printDebug("_unpad", "len of obj: {}".format(len(obj)))
        pad = set(list(obj[-(pad_len + 2):-2]))
        if len(pad) == 1 and 0 in pad:
            printDebug("_unpad", "found ANSIX923 like padding")
            return obj[:-(pad_len + 2)]

        # Otherwise, try to detect our PKCS7 like padding.
        pad_len = obj[-1]
        if pad_len == 2 and int.from_bytes(obj[-2:-1], byteorder = "big") == 2:
            printDebug("_unpad", "last 2 bytes are pad")
            return obj[:-2]
        elif pad_len == 1:
            printDebug("_unpad", "last byte is pad")
            return obj[:-1]

        printDebug("_unpad", "no padding detected")
        # No padding detected, return the object as is.
        return obj

    # Create adjusted file offset and size.
    def _calc_offsets(self, offset, size, path):
        # Calculate how many bytes to ignore from the beginning of the first extent.
        first = offset % 4096

        # Calculate how many bytes to ignore from the end of the last extent.
        if (first + size) % 4096 == 0:
            last = 0
        else:
            last = 4096 - ((first + size) % 4096)

        # Generate new offset.
        # FIXME: correct this for files over 256 extents in size.
        header_len = self._file_cache[path]["header_len"] + 2 * 4096
        offset = offset - (offset % 4096) + header_len + 8

        # Adjust size to a multiple of a full extent.
        if size % 4096 == 0:
            new_size = size
        else:
            new_size = size + 4096 - (size % 4096)

        return offset, new_size, first, last

    def _read_policy_file(self, directory):
        if os.path.isdir(directory):
            try:
                f = open(directory + "/.policy")
            except IOError:
                return self._policy

            return f.read()

        return self._policy

    ### File operations.

    # Get file attributes.
    def getattr(self, path, fd = None):
        path = self._full_path(path)
        st = os.lstat(path)
        attrs = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        try:
            attrs["st_size"] -= self._file_cache[path]["header_len"] + 2 * 4096 + 8
        except:
            attrs["st_size"] -= 3 * 4096
        return attrs

    # Read the target of a symbolic link.
    def readlink(self, path):
        dirpath = os.readlink(self._full_path(path))
        if dirpath.startswith("/"):
            return os.path.relpath(dirpath, self.root)
        else:
            return dirpath

    # Create a file node.
    def mknod(self, path, mode, dev):
        return os.mknod(self._full_path(path), mode, dev)

    # Create a directory.
    def mkdir(self, path, mode):
        return os.mkdir(self._full_path(path), mode)

    # Remove a file.
    def unlink(self, path):
        return os.unlink(self._full_path(path))

    # Remove a directory.
    def rmdir(self, path):
        return os.rmdir(self._full_path(path))

    # Create a symbolic link.
    def symlink(self, path, target):
        return os.symlink(target, self._full_path(path))

    # Rename a file.
    def rename(self, old_path, new_path):
        return os.rename(self._full_path(old_path), self._full_path(new_path))

    # Create a hard link.
    def link(self, target, path):
        return os.link(self._full_path(path), target)

    # Change permission bits of a file.
    def chmod(self, path, mode):
        return os.chmod(self._full_path(path), mode)

    # Change the owner of a file.
    def chown(self, path, user, group):
        return os.chown(self._full_path(path), user, group)

    # Change the size of a file.
    def truncate(self, path, size):
        printDebug("truncate", "truncating {} to {} bytes".format(path, size))
        # FIXME: Must decrypt last block and truncate that, then encrypt it again.
        with open(self._full_path(path), "r+") as f:
            f.truncate(size)

    # Open a file.
    def open(self, path, flags):
        # TODO: Determine if opening in write only mode will cause problems with metadata.
        path = self._full_path(path)
        printDebug("open", "opening {} with flags {}".format(path, flags))

        fd = os.open(path, flags)
        # Open in read only mode to read metadata.
        #fd = os.open(path, os.O_RDONLY)

        # Setup file context in the cache.
        self._file_cache[path] = self._read_metadata(fd)
        self._file_cache[path]["cache"] = []

        # Close and re-open file with correct flags.
        #os.close(fd)

        return fd

    # Read from a file.
    def read(self, path, size, offset, fd):
        path = self._full_path(path)
        uid, gid, pid = fuse_get_context()
        printDebug("read", "reading {} bytes from {} (fd {}) at offset {}".format(size, path, fd, offset))
        printDebug("read", uid)
        printDebug("read", gid)

        if uid not in self._user_cache:
            self._generate_user_attr()

        # Fetch user's cached key.
        key = self._user_cache[uid]["key"]

        # Fetch the encrypted AES key.
        c1 = self._file_cache[path]["c1"]

        # Calculate the first extent to read based on the offset.
        e = int(offset / 4096)

        # Adjust offset to account for cryptographic metadata, seek, and read.
        offset, new_size, first, last = self._calc_offsets(offset, size, path)
        printDebug("read", "adjusted offset: {}".format(offset))
        printDebug("read", "adjusted size: {}".format(new_size))
        printDebug("read", "first: {}".format(first))
        printDebug("read", "last: {}".format(last))
        os.lseek(fd, offset, os.SEEK_SET)
        b = os.read(fd, new_size)

        # Process read data, decrypting each read extent.
        plaintexts = []
        printDebug("read", "e: {}".format(e))
        num_extents = ceil(new_size / 4096.0)

        for i in range(num_extents):
            printDebug("read", "index: {}".format(e + i))
            # Get IV and tag for extent e + i.
            iv = self._file_cache[path]["IV"][e + i]
            tag = self._file_cache[path]["tags"][e + i]
            printDebug("read", "tag length: {}".format(len(tag)))
            printDebug("read", "tag: {}".format(tag))
            #printDebug("read", "ct: {}".format(b[i:i + 4096]))

            # Perform decryption
            msg = self._abe.decrypt(key, c1, b[i:i + 4096], iv, tag)
            if not msg:
                # Attempt to unpad last block before breaking out of loop.
                if i > 0:
                    plaintexts[i] = self._unpad(plaintexts[i])

                break

            # Remove padding if last block.
            if i == num_extents -1:
                msg = self._unpad(msg)

            # Store message in both list to be returned and the cache.
            plaintexts.append(msg)
            printDebug("read", "decrypted msg: {}".format(msg))
            self._file_cache[path][e + i] = msg

        # Adjust plaintext to contain only what was requested.
        p = b"".join(plaintexts)
        p = p[first:] # Drop unrequested bytes at beginning.
        if last:
            p = p[:-last] # Drop unrequested bytes at end.
        printDebug("read", "requested {} bytes, returning {} bytes".format(size, len(p)))
        return p

    # Write to a file.
    def write(self, path, data, offset, fd):
        path = self._full_path(path)
        printDebug("write", "writing to {} (fd {}) at offset {}".format(path, fd, offset))
        printDebug("write", "writing {} bytes".format(len(data)))

        uid, gid, pid = fuse_get_context()
        if uid not in self._user_cache:
            self._generate_user_attr()

        # Fetch user's cached key and policy.
        key = self._user_cache[uid]["key"]
        policy = self._read_policy_file(path)

        # Fetch the encrypted AES key.
        c1 = self._file_cache[path]["c1"]

        # Calculate the first extent to read based on the offset.
        e = int(offset / 4096)
        printDebug("write", "e: {}".format(e))

        # Calculate new offset and seek.
        offset, new_size, first, last = self._calc_offsets(offset, len(data), path)
        os.lseek(fd, offset, os.SEEK_SET) 
        printDebug("write", "new offset: {}".format(offset))
        printDebug("write", "new size: {}".format(new_size))

        # Prepare data to be written to the cache. Prepend the missing bytes of
        # the first extent and append the missing bytes of the last extent from
        # the cache.
        num_extents = int(ceil(new_size / 4096.0))
        printDebug("write", "# of extents: {}".format(num_extents))
        try:
            prepend = self._file_cache[path][e][:first + 1]
        except KeyError:
            prepend = b""

        try:
            append = self._file_cache[path][e + num_extents][-last]
        except KeyError:
            append = b""

        data = prepend + data + append
        printDebug("write", "new length of data: {}".format(len(data)))
        #assert len(data) % 4096 == 0 # Ensure I'm not breaking everything...
        data_list = [data[i:i+4096] for i in range(0, len(data), 4096)]

        # Encrypt each extent.
        ciphertexts = []
        for i in range(num_extents):
            printDebug("write", "index: {}".format(e + i))
            # Write to cache.
            try:
                self._file_cache[path]["cache"][e + i] = data_list[i]
            except IndexError:
                cachelen = len(self._file_cache[path]["cache"])
                printDebug("write", "cache size {} and index {}".format(cachelen,
                                                                        e + i))
                assert cachelen == e + i
                self._file_cache[path]["cache"].append(data_list[i])

            #printDebug("write", "msg: {}".format(data_list[i]))
            # Encrypt extent.
            if len(data_list[i]) % 4096:
                c, iv, tag = self._abe.encrypt(self._pad(data_list[i]), key, c1)
            else:
                c, iv, tag = self._abe.encrypt(data_list[i], key, c1)

            #printDebug("write", "ct: {}".format(c))
            printDebug("write", "length of tag: {}".format(len(tag)))
            printDebug("write", "tag: {}".format(tag))
            ciphertexts.append(c)
            printDebug("write", "length of ct: {}".format(len(c)))
            self._file_cache[path]["IV"][e + i] = iv
            self._file_cache[path]["tags"][e + i] = tag

        c = b"".join(ciphertexts)
        printDebug("write", "ct len: {}".format(len(c)))
        os.fsync(fd)
        return os.write(fd, c)

    # Get filesystem statistics.
    def statfs(self, path):
        path = self._full_path(path)
        stv = os.statvfs(path)
        stats = dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
                'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
                'f_frsize', 'f_namemax'))
        printDebug("statfs", "getting stat of {}: {}".format(path, stats))
        return stats

    # Try to flush cached data.
    def flush(self, path, fd):
        path = self._full_path(path)
        printDebug("flush", "flushing {} (fd {})".format(path, fd))
        return os.fsync(fd)

    # Release an open file.
    def release(self, path, fd):
        path = self._full_path(path)
        printDebug("release", "releasing {}".format(path))
        os.lseek(fd, 0, os.SEEK_SET)

        c1 = self._abe.toBytes(self._file_cache[path]["c1"])
        #c1_len = ceil((len(c1) + 8) / 4096.0)
        c1_len = self._file_cache[path]["header_len"]
        printDebug("release", "header_len: {}".format(c1_len))
        assert c1_len * 4096 >= len(c1)
        c1 = self._pad(c1_len.to_bytes(8, byteorder = "big") + c1)
        printDebug("release", "length of c1 + 8: {}".format(len(c1)))
        #printDebug("release", "IVs: {}".format(self._file_cache[path]["IV"]))
        #printDebug("release", "tags: {}".format(self._file_cache[path]["tags"]))
        IVs = self._pad(b"".join(self._file_cache[path]["IV"]))
        tags = self._pad(b"".join(self._file_cache[path]["tags"]))

        printDebug("release", "length of IVs ({}): {}".format(path, len(IVs)))
        printDebug("release", "length of tags({}): {}".format(path, len(tags)))
        printDebug("release", "header size: {}".format(len(c1 + IVs + tags)))
        os.write(fd, c1 + IVs + tags)
        del self._file_cache[path]

        return os.close(fd)

    # Synchronize file contents.
    def fsync(self, path, datasync, fd):
        path = self._full_path(path)
        printDebug("fsync", "fsyncing {} ({})".format(path, fd))
        # FIXME: write all metadata to file first!
        return self.flush(self._full_path(path), fd)

    # Set extended attributes.
    #def setxattr(self, path, name, value, flags):
    #    pass

    # Get extended attributes.
    #def getxattr(self, path, name):
    #    return os.getxattr(path, name)

    # List extended attributes.
    #def listxattr(self, path):
    #    pass

    # Remove extended attributes.
    #def removexattr(self, path, name):
    #    pass

    # Open a directory.
    #def opendir(self, path):
    #    return 0

    # Read a directory.
    def readdir(self, path, offset):
        path = self._full_path(path)
        dirents = [".", ".."]

        if os.path.isdir(path):
            dirents.extend(os.listdir(path))

        # Remove policy file so it is not seen.
        dirents = [x for x in dirents if x != ".policy"]

        for r in dirents:
            yield r

    # Release a directory.
    #def releasedir(self, path, offset):
    #    pass

    # Synchronize directory contents.
    #def fsyncdir(self, path, flags):
    #    pass

    # Initialize a filesystem.
    #def init(self):
    #    pass

    # Cleanup a filesystem.
    #def destroy(self):
    #    pass

    # Check file access permissions.
    def access(self, path, mode):
        if not os.access(self._full_path(path), mode):
            raise FuseOSError(errno.EACCES)

    # Create and open a file.
    def create(self, path, mode):
        path = self._full_path(path)
        printDebug("create", "creating {} with mode {}".format(path, mode))
        # Generate null metadata.
        self._file_cache[path] = {}

        # Need to generate a new AES key.
        user = self._getusername()
        if user not in self._user_cache:
            self._generate_user_attr()

        policy = self._read_policy_file(path)
        c1 = self._abe.genAESKey(policy)
        printDebug("create", "length of c1: {}".format(len(c1)))
        self._file_cache[path] = {"c1": c1,
                                  "IV": [b"\x00" * 16] * 16,
                                  "tags": [b"\x00" * 16] * 16}
        self._file_cache[path]["cache"] = []
        header_len = len(self._pad(self._abe.toBytes(c1) + b"\x00" * 8)) - 8
        self._file_cache[path]["header_len"] = header_len
        printDebug("create", "header_len: {}".format(header_len))

        return os.open(path, os.O_WRONLY | os.O_CREAT, mode)

    # Change the size of an open file.
    #def ftruncate(self, path, offset, fd):
    #    pass

    # Get attributes from an open file.
    #def fgetattr(self, path, fd):
    #    pass

    # Perform POSIX file locking operation.
    #def lock(self, path, fip, cmd, lock):
    #    pass

    # Change the access and modification times of a file with nanosecond 
    # resolution.
    def utimens(self, path, time = None):
        return os.utime(self._full_path(path), time)

    # Map block index withing file to block index within device.
    #def bmap(self, path, blocksize, index):
    #    pass

    # Ioctl.
    #def ioctl(self, path, cmd, arg):
    #    pass

    # Poll for IO readiness events.
    #def poll(self, path, args):
    #    pass

    # Write contents of a buffer to an open file.
    #def write_buf(self, path, buf, offset, fd):
    #    pass

    # Store data from an open file into a buffer.
    #def read_buf(self, path, size, offset, fd):
    #    pass

    # Perform BSD style locking operations.
    #def flock(self, path, op):
    #    pass

    # Allocate space for an open file.
    #def fallocate(self, path, flags, offset_1, offset_2):
    #    pass

# Helper functions.
def printDebug(op, msg):
    if DEBUG:
        print("[DEBUG {}]: {}".format(op, msg))

def print_usage():
    print("Usage: {}".format(sys.arv[0]))
    sys.exit(2)

# main function.
def main(mountpoint, root):
    FUSE(ABEFS(root), mountpoint, nothreads = True, foreground = True, allow_other = True)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print_usage()

    mountpoint = sys.argv[2]
    root = sys.argv[1]
    print("mounting '{}' on '{}'".format(root, mountpoint))
    main(mountpoint, root)
