#!/usr/bin/python3
# coding: utf-8

from setuptools import setup, find_packages


setup(name='pybtc',
      version='0.1',
      description='Python Bitcoin library',
      keywords='bitcoin',
      url='https://github.com/bitaps-com/pybtc',
      author='Alexsei Karpov',
      author_email='admin@bitaps.com',
      license='GPL-3.0',
      packages=find_packages(),
      install_requires=[ 'secp256k1', ],
      include_package_data=True,
      zip_safe=False)

#
# from distutils.core import setup
#
# setup(name='pybtc',
#       version='1.0.1',
#       description='Bitcoin library',
#       author='Alexsei Karpov',
#       author_email='admin@bitaps.com',
#       url='https://github.com/bitaps-com/pybtc',
#       packages=['pybtc'],
#
#       )
