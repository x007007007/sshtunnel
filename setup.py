#!/usr/bin/env python

from setuptools import setup


setup(name='sshsocks',
      version='0.2.1',
      description='SSH socks proxy',
      long_description=open('README.md').read(),
      author='x007007007',
      author_email='x007007007@126.com',
      url='https://github.com/x007007007/sshtunnel',
      install_requires=['paramiko'],
      package_dir = {'': 'src'},
      packages=['SocksService'],
      scripts=['script/sshsocks.py'],
      data_files=[('config', ['cfg/sshsocks.conf'])]
     )
