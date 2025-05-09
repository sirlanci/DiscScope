import logging
import os
import tempfile

log = logging.getLogger(name=__name__)

def find_bin(name):
    """Searches the environment for a program with the provided name."""
    for dir in os.environ['PATH'].split(':'):
        can = os.path.join(dir, name)
        if os.path.isfile(os.path.realpath(can)):
            return can
    return None

def mkdir(dir_path=None):
    """Creates the provided directory if it does not already exist.

    Keyword Arguments:
    dir_path -- Path to create. If None, a temporary directory is created.

    Returns:
    Path to created directory, or None if it couldn't be created.
    """
    if dir_path is None:
        return tempfile.mkdtemp()

    if not os.path.isdir(os.path.realpath(dir_path)):
        if os.path.exists(dir_path):
            log.error("%s exists and is not a directory" % dir_path)
            return None

        try:
            os.mkdir(dir_path)
        except Exception as ex:
            log.error("Failed to create directory %s: %s" % (dir_path, str(ex)))
            return None

    return dir_path

def mksfile(dir, mode, prefix=None):
    """Creates a unique file and returns an opened file object.

    Keyword Arguments:
    dir -- Directory to make the file in.
    mode -- Mode to open the file in (ex: 'w').
    prefix -- An optional prefix for the created file.

    Returns:
    A tuple of open file and opened filepath.
    """
    fd, fp = tempfile.mkstemp(prefix=prefix, dir=dir)
    fo = os.fdopen(fd, mode)
    return (fo, fp)
