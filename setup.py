# -*- coding: utf-8 -*-
import sys
from setuptools import setup

PKG_NAME = "PythonForWindows"
VERSION  = "0.5"

if sys.version_info[0] != 2:
    print("PythonForWindows python3 support is still in beta, feel free to send feedback")


setup(
    name = PKG_NAME,
    version = VERSION,
    author = 'Hakril',
    author_email = 'none',
    description = 'A codebase aimed to make interaction with Windows and native execution easier',
    license = 'BSD',
    keywords = 'windows python',
    url = 'https://github.com/hakril/PythonForWindows',
    packages = ['windows',
                'windows.crypto',
                'windows.debug',
                'windows.generated_def',
                'windows.native_exec',
                'windows.rpc',
                'windows.utils',
                'windows.winobject',
                'windows.winproxy',
                'windows.winproxy.apis'],
    classifiers = ['Programming Language :: Python :: 2 :: Only',
                   'Programming Language :: Python :: 2.7']
)