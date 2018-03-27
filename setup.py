from setuptools import setup
# -*- coding: utf-8 -*-

PKG_NAME = "PythonForWindows"
VERSION  = "0.4"


setup(
    name = PKG_NAME,
    version = VERSION,
    author = 'Hakril',
    author_email = 'none',
    description = 'A codebase aimed to make interaction with Windows and native execution easier',
    license = 'BSD',
    keywords = 'windows python',
    url = '',
    packages = ['windows',
                'windows.crypto',
                'windows.debug',
                'windows.generated_def',
                'windows.native_exec',
                'windows.rpc',
                'windows.utils',
                'windows.winobject'],
)