from os.path import abspath
from os.path import dirname
from os.path import join as joinpath
from os.path import realpath

def _badpath(path, base):
    """Determines if a given file path is under a given base path or not.
    :param str path: file path where the file will be extracted to.
    :param str base: path to the current working directory.
    :return: False, if the path is under the given base, else True.
    :rtype: bool
    """
    # joinpath will ignore base if path is absolute
    return not realpath(abspath(joinpath(base, path))).startswith(base)


def _badlink(info, base):
    """Determine if a given link is under a given base path or not.
    :param TarInfo info: file that is going to be extracted.
    :param str base: path to the current working directory.
    :return: False, if the path is under the given base, else True.
    :rtype: bool
    """
    # Links are interpreted relative to the directory containing the link
    tip = realpath(abspath(joinpath(base, dirname(info.name))))
    return _badpath(info.linkname, base=tip)


def get_safe_members_in_tar_file(tarfile):
    """Retrieve members of a tar file that are safe to extract.
    :param Tarfile tarfile: the archive that has been opened as a TarFile
        object.
    :return: list of members in the archive that are safe to extract.
    :rtype: list
    """
    base = realpath(abspath(('.')))
    result = []
    for finfo in tarfile.getmembers():
        if _badpath(finfo.name, base):
            print(finfo.name + ' is blocked: illegal path.')
        elif finfo.issym() and _badlink(finfo, base):
            print(finfo.name + ' is blocked: Symlink to ' + finfo.linkname)
        elif finfo.islnk() and _badlink(finfo, base):
            print(finfo.name + ' is blocked: Hard link to ' + finfo.linkname)
        else:
            result.append(finfo)
    return result