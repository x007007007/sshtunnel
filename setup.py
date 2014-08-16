#!/usr/bin/env python

from setuptools import setup
from ez_setup import use_setuptools
use_setuptools()

setup(name='sshtunnel',
      version='0.1',
      description='SSH socks proxy',
      author='x007007007',
      author_email='x007007007@126.com',
      url='https://github.com/x007007007/sshtunnel',
      install_requires=['paramiko'],
      package_dir = {'': 'src'},
      packages=['socksService'],
      scripts=['script/sshtunnel.py']
     )
