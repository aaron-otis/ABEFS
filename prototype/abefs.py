# Version 0.3

import os, sys, errno
from fuse import FUSE, FuseOSError, Operations
from crypto import ABECrypto
from pwd import getpwuid
from json import dumps, loads
from math import ceil

# Representation of a file with ABE metadata. Uses a hybrid encryption 
# scheme to derive an AES key from a random group element.
class ABEFile:
    def __init__(self, ciphertext):
        self.abe_metadata = ciphertext["c1"]
        self.aes_metadata = ciphertext["c2"]
        self.aes_metadata["msg"] = loads(self.aes_metadata["msg"])
# BEGIN DEBUG
        #for k, v in self.aes_metadata.items():
        #    printDebug("__init__", "{}: '{}'".format(k, v))
        #    print
# END DEBUG

# FUSE class.
class ABEFS(Operations):
    def __init__(self, root):
        self.root = root
        self._abe = ABECrypto()
        self._user_cache = {}
        self._file_cache = {}
        self._header_len = 4096

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
        user = self._getusername()
        uid = str(os.getuid())
        attr_list = [uid]
        self._user_cache[user] = {"attr": attr_list, 
                                  "key": self._abe.get_secret_key(attr_list),
                                  "policy": "({} or 0)".format(uid)}

    # Read the first block of a file to get its ABE metatdata.
    def _read_metadata(self, fd):
        os.lseek(fd, 0, os.SEEK_SET)

        # Read CP-ABE header data.
        raw_bytes = os.read(fd, self._header_len).rstrip(b"\x00")
        printDebug("_read_metadata", "length of raw c1: {}".format(len(raw_bytes)))
        c1 = self._abe.fromBytes(raw_bytes)

        # Read IV data.
        raw_bytes = os.read(fd, 4096).rstrip(b"\x00")
        IVs = []
        for i in range(0, len(raw_bytes), 16):
            IVs.append(raw_bytes[i: i + 16])
        printDebug("_read_metadata", "IVs {}".format(IVs))
        iv_len = len(IVs)
        IVs += [b"\x00" * 16] * (256 - iv_len % 256)
        printDebug("_read_metadata", "IV len {}".format(len(IVs)))

        # Read tag data.
        raw_bytes = os.read(fd, 4096).rstrip(b"\x00")
        MACs = []
        for i in range(0, len(raw_bytes), 16):
            MACs.append(raw_bytes[i: i + 16])
        printDebug("_read_metadata", "tags {}".format(MACs))
        tag_len = len(MACs)
        MACs += [b"\x00" * 16] * (256 - tag_len % 256)
        printDebug("_read_metadata", "tag len {}".format(len(MACs)))

        return {"c1": c1, "IV": IVs, "tags": MACs}

    # Writes metadata to a file.
    def _write_metadata(self, fd):
        pass

    # Zero pad.
    def _pad(self, obj):
        size = len(obj)

        return obj + bytes(4096 - size % 4096)

    # Create adjusted file offset and size.
    def _adjust_offset_size(self, offset, size):
        # Generate new offset. FIXME: correct this for files over 256 extents in size.
        offset = offset + self._header_len + 2 * 4096

        # Adjust size to a multiple of a full extent.
        new_size = size + size % 4096

        return offset, new_size

    ### File operations.

    # Get file attributes.
    def getattr(self, path, fd = None):
        path = self._full_path(path)
        st = os.lstat(path)
        attrs = dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
                'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))
        attrs["st_size"] -= self._header_len + 2 * 4096
        #printDebug("getattr", "attributes of {}: {}".format(path, attrs))
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

        # Setup file context in the cache.
        self._file_cache[path] = self._read_metadata(fd)
        self._file_cache[path]["cache"] = {}

        return fd

    # Read from a file.
    def read(self, path, size, offset, fd):
        # Get user's key and preform decryption on the contents of fd.
        printDebug("read", "reading {} bytes from {} (fd {}) at offset {}".format(size, path, fd, offset))

        # TODO: Determine attributes in a better way, maybe like eCryptfs.
        user = self._getusername()
        if user not in self._user_cache:
            self._generate_user_attr()

        # Fetch user's cached key.
        key = self._user_cache[user]["key"]

        # Fetch the encrypted AES key.
        c1 = self._file_cache[self._full_path(path)]["c1"]

        offset, new_size = self._adjust_offset_size(offset, size)
        printDebug("read", "adjusted offset: {}".format(offset))
        os.lseek(fd, offset, os.SEEK_SET)
        b = os.read(fd, new_size)

        # Process read data, decrypting each read extent.
        plaintexts = []
        e = int(size / 4096) # The number of the first extent to be read.
        printDebug("read", "e: {}".format(e))
        num_extents = ceil(new_size / 4096.0)
        for i in range(num_extents):
            printDebug("read", "index: {}".format(e * i))
            iv = self._file_cache[self._full_path(path)]["IV"][e * i]
            tag = self._file_cache[self._full_path(path)]["tags"][e * i]
            printDebug("read", "tag length: {}".format(len(tag)))
            printDebug("read", "tag: {}".format(tag))
            plaintexts.append(self._abe.decrypt(key, c1, b[i:i + 4096], iv, tag))

        return b"".join(plaintexts)

    # Write to a file.
    def write(self, path, data, offset, fd):
        printDebug("write", "writing to {} (fd {}) at offset {}".format(path, fd, offset))
        printDebug("write", "writing {} bytes".format(len(data)))

        # TODO: Determine attributes in a better way, maybe like eCryptfs.
        user = self._getusername()
        if user not in self._user_cache:
            self._generate_user_attr()

        # Fetch user's cached key and policy.
        key = self._user_cache[user]["key"]
        policy = self._user_cache[user]["policy"]

        # Fetch the encrypted AES key.
        c1 = self._file_cache[self._full_path(path)]["c1"]

        offset, new_size = self._adjust_offset_size(offset, len(data))
        os.lseek(fd, offset, os.SEEK_SET) 
        printDebug("write", "new offset: {}".format(offset))

        # Encrypt each extent.
        ciphertexts = []
        e = offset / 4096.0 - 3
        printDebug("write", "e: {}".format(e))
        e = int(e)
        num_extents = int(ceil(new_size / 4096.0))
        for i in range(num_extents):
            printDebug("write", "index: {}".format(e + i))
            c, iv, tag = self._abe.encrypt(data[e: e + 4096], key, c1)
            printDebug("write", "length of tag: {}".format(len(tag)))
            printDebug("write", "tag: {}".format(tag))
            ciphertexts.append(c)
            self._file_cache[self._full_path(path)]["IV"][e + i] = iv
            self._file_cache[self._full_path(path)]["tags"][e + i] = tag

        return os.write(fd, b"".join(ciphertexts))

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
        # FIXME: write all metadata to file before calling fsync!
        return os.fsync(fd)

    # Release an open file.
    def release(self, path, fd):
        path = self._full_path(path)
        printDebug("release", "releasing {}".format(path))
        os.lseek(fd, 0, os.SEEK_SET)

        c1 = self._pad(self._abe.toBytes(self._file_cache[path]["c1"]))
        printDebug("release", "length of c1: {}".format(len(self._abe.toBytes(self._file_cache[path]["c1"]))))
        IVs = self._pad(b"".join(self._file_cache[path]["IV"]))
        tags = self._pad(b"".join(self._file_cache[path]["tags"]))

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

        policy = self._user_cache[user]["policy"]
        c1 = self._abe.genAESKey(policy)
        printDebug("create", "length of c1: {}".format(len(c1)))
        self._file_cache[path] = {"c1": c1,
                                  "IV": [b"\x00" * 16] * 16,
                                  "tags": [b"\x00" * 16] * 16}

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
    print("[DEBUG {}]: {}".format(op, msg))

def print_usage():
    print("Usage: {}".format(sys.arv[0]))
    sys.exit(2)

# main function.
def main(mountpoint, root):
    FUSE(ABEFS(root), mountpoint, nothreads = True, foreground = True)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print_usage()

    mountpoint = sys.argv[2]
    root = sys.argv[1]
    print("mounting '{}' on '{}'".format(root, mountpoint))
    main(mountpoint, root)
