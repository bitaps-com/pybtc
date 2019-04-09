#!/usr/bin/python3
# coding: utf-8

from setuptools import setup, find_packages


l = "https://github.com/bitcoin-core/secp256k1/archive/master.zip"

setup(name='pybtc',
      version='2.0.9',
      description='Python Bitcoin library',
      keywords='bitcoin',
      url='https://github.com/bitaps-com/pybtc',
      author='Alexsei Karpov',
      author_email='admin@bitaps.com',
      license='GPL-3.0',
      include_package_data=True,
      package_data={
          'pybtc': ['bip39_word_list/*.txt', 'test/*.txt'],
      },
      dependency_links = ['https://github.com/bitcoin-core/secp256k1/tarball/master'],
      setup_requires=['cffi>=1.3.0', 'pytest-runner==2.6.2'],
      install_requires=['cffi>=1.3.0'],
      tests_require=['pytest==2.8.7'],

      packages=find_packages(exclude=('_cffi_build', '_cffi_build.*', 'libsecp256k1')),
      ext_package="secp256k1",
      test_suite='tests',
      zip_safe=False)


