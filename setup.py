import errno
import os.path
from setuptools import setup, find_packages, Extension
from setup_tools import *
from distutils.command.build_clib import build_clib as _build_clib
from distutils.command.build_ext import build_ext as _build_ext



class build_clib(_build_clib):
    def initialize_options(self):
        _build_clib.initialize_options(self)
        self.build_flags = None

    def finalize_options(self):
        _build_clib.finalize_options(self)
        if self.build_flags is None:
            self.build_flags = {
                'include_dirs': [],
                'library_dirs': [],
                'define': [],
            }

    def get_source_files(self):
        # Ensure library has been downloaded (sdist might have been skipped)
        download_library(self)

        return [
            absolute(os.path.join(root, filename))
            for root, _, filenames in os.walk(absolute("libsecp256k1"))
            for filename in filenames
        ]

    def build_libraries(self, libraries):
        raise Exception("build_libraries")

    def check_library_list(self, libraries):
        raise Exception("check_library_list")

    def get_library_names(self):
        return build_flags('libsecp256k1', 'l', os.path.abspath(self.build_temp))

    def run(self):
        build_temp = os.path.abspath(self.build_temp)

        try:
            os.makedirs(build_temp)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise

        if not os.path.exists(absolute("libsecp256k1/configure")):
            # configure script hasn't been generated yet
            autogen = absolute("libsecp256k1/autogen.sh")
            os.chmod(absolute(autogen), 0o755)
            subprocess.check_call(
                [autogen],
                cwd=absolute("libsecp256k1"),
            )

        for filename in [
            "libsecp256k1/configure",
            "libsecp256k1/build-aux/compile",
            "libsecp256k1/build-aux/config.guess",
            "libsecp256k1/build-aux/config.sub",
            "libsecp256k1/build-aux/depcomp",
            "libsecp256k1/build-aux/install-sh",
            "libsecp256k1/build-aux/missing",
            "libsecp256k1/build-aux/test-driver",
        ]:
            try:
                os.chmod(absolute(filename), 0o755)
            except OSError as e:
                # some of these files might not exist depending on autoconf version
                if e.errno != errno.ENOENT:
                    # If the error isn't "No such file or directory" something
                    # else is wrong and we want to know about it
                    raise

        cmd = [
            absolute('libsecp256k1/configure'),
            '--disable-shared',
            '--enable-static',
            '--disable-dependency-tracking',
            '--with-pic',
            '--enable-module-recovery',
            '--disable-jni',
            '--prefix',
            os.path.abspath(self.build_clib),
            '--enable-experimental',
            '--enable-module-ecdh',
            '--enable-benchmark=no',
            '--enable-endomorphism',
        ]

        log.debug('Running configure: {}'.format(' '.join(cmd)))
        subprocess.check_call(cmd, cwd=build_temp)

        subprocess.check_call([MAKE], cwd=build_temp)
        subprocess.check_call([MAKE, 'install'], cwd=build_temp)

        self.build_flags['include_dirs'].extend(build_flags('libsecp256k1', 'I', build_temp))
        self.build_flags['library_dirs'].extend(build_flags('libsecp256k1', 'L', build_temp))



class build_ext(_build_ext):
    def run(self):
        if self.distribution.has_c_libraries():
            build_clib = self.get_finalized_command("build_clib")
            self.include_dirs.append(
                os.path.join(build_clib.build_clib, "include"),
            )
            self.include_dirs.extend(build_clib.build_flags['include_dirs'])

            self.library_dirs.append(
                os.path.join(build_clib.build_clib, "lib"),
            )
            self.library_dirs.extend(build_clib.build_flags['library_dirs'])

            self.define = build_clib.build_flags['define']
        return _build_ext.run(self)

setup(name='pybtc',
      version='2.3.7',
      description='Python Bitcoin library',
      keywords='bitcoin',
      url='https://github.com/bitaps-com/pybtc',
      author='Alexsei Karpov',
      author_email='admin@bitaps.com',
      python_requires='>=3.7',
      license='GPL-3.0',
      package_data={
          'pybtc': ['bip39_word_list/*.txt', 'test/*.txt'],
      },
      cmdclass={
        'build_clib': build_clib,
        'build_ext': build_ext,
        'egg_info': egg_info,
        'sdist': sdist,
        'bdist_wheel': bdist_wheel
      },
      options={"bdist_wheel": {"universal": True}},
      distclass=Distribution,
      ext_modules=[Extension("cache_strategies", ["pybtc/cache_strategies/cache.c"]),
                   Extension("_sha3_hash", ["pybtc/_crypto_c/sha3.c"]),
                   Extension("_bitarray", ["pybtc/bitarray/_bitarray.c"]),
                   Extension("_secp256k1", ["pybtc/_secp256k1/module_secp256k1.c"],
                             include_dirs=["libsecp256k1/include/", "libsecp256k1/src/"]),
                   Extension("_crypto",
                             ["pybtc/_crypto/crypto/aes.cpp",
                              "pybtc/_crypto/module_crypto.cpp",
                              "pybtc/_crypto/crypto/hmac_sha256.cpp",
                              "pybtc/_crypto/crypto/hmac_sha512.cpp",
                              "pybtc/_crypto/crypto/sha256.cpp",
                              "pybtc/_crypto/crypto/sha256_avx2.cpp",
                              "pybtc/_crypto/crypto/sha256_shani.cpp",
                              "pybtc/_crypto/crypto/sha256_sse4.cpp",
                              "pybtc/_crypto/crypto/sha256_sse41.cpp",
                              "pybtc/_crypto/crypto/sha512.cpp",
                              "pybtc/_crypto/crypto/compat/glibc_compat.cpp",
                              "pybtc/_crypto/crypto/compat/glibc_sanity.cpp",
                              "pybtc/_crypto/crypto/compat/glibcxx_sanity.cpp",
                              "pybtc/_crypto/crypto/compat/strnlen.cpp",
                              "pybtc/_crypto/crypto/base58.cpp",
                              "pybtc/_crypto/crypto/hash.cpp",
                              "pybtc/_crypto/crypto/uint256.cpp",
                              "pybtc/_crypto/crypto/utilstrencodings.cpp",
                              ],
                             extra_compile_args=['-std=c++11'],
                             include_dirs=["pybtc/_crypto/crypto/"])
                   ],

      packages=find_packages(exclude=('libsecp256k1')),
      test_suite='tests',
      zip_safe=False)



