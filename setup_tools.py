import glob
import platform
import os
import shutil
from contextlib import contextmanager
from tempfile import mkdtemp
from setuptools import __version__ as setuptools_version
import subprocess
import tarfile
from distutils import log
from io import BytesIO


from distutils import log
from setuptools import Distribution as _Distribution
from setuptools.command.sdist import sdist as _sdist
from setuptools.command.egg_info import egg_info as _egg_info

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import URLError


try:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:
    _bdist_wheel = None
    pass

# We require setuptools >= 3.3
if [int(i) for i in setuptools_version.split('.', 2)[:2]] < [3, 3]:
    raise SystemExit(
        'Your setuptools version ({}) is too old to correctly install this '
        'package. Please upgrade to a newer version (>= 3.3).'.format(setuptools_version)
    )



MAKE = 'gmake' if platform.system() in ['FreeBSD'] else 'make'
LIB_URL = 'https://github.com/bitaps-com/secp256k1/tarball/master'

class Distribution(_Distribution):
    def has_c_libraries(self):
        return True


def download_library(command):
    if command.dry_run:
        return
    libdir = absolute("libsecp256k1")
    if os.path.exists(os.path.join(libdir, "autogen.sh")):
        # Library already downloaded
        return
    if not os.path.exists(libdir):
        command.announce("downloading libsecp256k1 source code", level=log.INFO)
        try:
            r = urlopen(LIB_URL)
            if r.getcode() == 200:
                content = BytesIO(r.read())
                content.seek(0)
                with tarfile.open(fileobj=content) as tf:
                    dirname = tf.getnames()[0].partition('/')[0]
                    tf.extractall()
                shutil.move(dirname, libdir)
            else:
                raise SystemExit( "Unable to download secp256k1 library: HTTP-Status: %d", r.getcode())
        except URLError as ex:
            raise SystemExit("Unable to download secp256k1 library: %s", str(ex))

class egg_info(_egg_info):
    def run(self):
        # Ensure library has been downloaded (sdist might have been skipped)
        download_library(self)
        _egg_info.run(self)

class sdist(_sdist):
    def run(self):
        download_library(self)
        _sdist.run(self)


if _bdist_wheel:
    class bdist_wheel(_bdist_wheel):
        def run(self):
            download_library(self)
            _bdist_wheel.run(self)
else:
    bdist_wheel = None

@contextmanager
def workdir():
    cwd = os.getcwd()
    tmpdir = mkdtemp()
    os.chdir(tmpdir)
    try:
        yield
    finally:
        os.chdir(cwd)
        shutil.rmtree(tmpdir)


@contextmanager
def redirect(stdchannel, dest_filename):
    oldstdchannel = os.dup(stdchannel.fileno())
    dest_file = open(dest_filename, 'w')
    os.dup2(dest_file.fileno(), stdchannel.fileno())
    try:
        yield
    finally:
        if oldstdchannel is not None:
            os.dup2(oldstdchannel, stdchannel.fileno())
        if dest_file is not None:
            dest_file.close()


def absolute(*paths):
    op = os.path
    return op.realpath(op.abspath(op.join(op.dirname(__file__), *paths)))


def build_flags(library, type_, path):
    """Return separated build flags from pkg-config output"""

    pkg_config_path = [path]
    if "PKG_CONFIG_PATH" in os.environ:
        pkg_config_path.append(os.environ['PKG_CONFIG_PATH'])
    if "LIB_DIR" in os.environ:
        pkg_config_path.append(os.environ['LIB_DIR'])
        pkg_config_path.append(os.path.join(os.environ['LIB_DIR'], "pkgconfig"))

    options = ["--static", {'I': "--cflags-only-I", 'L': "--libs-only-L", 'l': "--libs-only-l"}[type_]]

    return [
        flag.strip("-{}".format(type_))
        for flag in subprocess.check_output(
            ["pkg-config"] + options + [library], env=dict(os.environ, PKG_CONFIG_PATH=":".join(pkg_config_path))
        )
        .decode("UTF-8")
        .split()
    ]




def detect_dll():
    here = os.path.dirname(os.path.abspath(__file__))
    for fn in os.listdir(os.path.join(here, 'libsecp256k1')):
        if fn.endswith('.dll'):
            return True
    return False