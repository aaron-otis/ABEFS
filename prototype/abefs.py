# Version 0.1

import os, sys, errno
from fuse import FUSE, FuseOSError, Operations

class ABEFS(Operations):
    def __init__(self, root):
        self.root = root

    def _full_path(self, path):
        if path.startswith("/"):
            path = path[1:]

        path = os.path.join(self.root, path)
        return path

    # Get file attributes.
    def getattr(self, path, fd = None):
        st = os.lstat(self._full_path(path))
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_ctime',
            'st_gid', 'st_mode', 'st_mtime', 'st_nlink', 'st_size', 'st_uid'))

    # Read target of a symbolic link.
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
        with open(self._full_path(path), "r+") as f:
            f.truncate(size)

    # Open a file.
    def open(self, path, flags):
        return os.open(self._full_path(path), flags)

    # Read from a file.
    def read(self, path, size, offset, fd):
        os.lseek(fd, offset, os.SEEK_SET) 
        return os.read(fd, size)

    # Write to a file.
    def write(self, path, data, offset, fd):
        os.lseek(fd, offset, os.SEEK_SET) 
        return os.write(fd, data)

    # Get filesystem statistics.
    def statfs(self, path):
        stv = os.statvfs(self._full_path(path))
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    # Try to flush cached data.
    def flush(self, path, fd):
        return os.fsync(fd)

    # Release an open file.
    def release(self, path, fd):
        return os.close(fd)

    # Synchronize file contents.
    def fsync(self, path, datasync, fd):
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
        return os.open(self._full_path(path), os.O_WRONLY | os.O_CREAT, mode)

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

def main(mountpoint, root):
    FUSE(ABEFS(root), mountpoint, nothreads = True, foreground = True)

if __name__ == "__main__":
    mountpoint = sys.argv[2]
    root = sys.argv[1]
    print("mounting '{}' on '{}'".format(root, mountpoint))
    main(mountpoint, root)
