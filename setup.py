# -*- coding: utf-8 -*-
import sys
import os.path
from setuptools import setup

PKG_NAME = "PythonForWindows"
VERSION  = "1.0.0"

# Load long description from README.md
this_directory = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(this_directory, 'README.md')) as f:
    long_description = f.read()

setup(
    name = PKG_NAME,
    version = VERSION,
    author = 'Hakril',
    author_email = 'pfw@hakril.net',
    description = 'A codebase aimed to make interaction with Windows and native execution easier',
    long_description=long_description,
    long_description_content_type='text/markdown',
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
    classifiers = ['Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 2.7']
)