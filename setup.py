from setuptools import setup
# -*- coding: utf-8 -*-

PKG_NAME = "PythonForWindows"
VERSION  = "0.1"


setup(
    name = PKG_NAME,
    version = VERSION,
    author = 'Hakril',
    author_email = 'none',
    description = 'Python wrapper around parts of Windows',
    license = 'BSD',
    keywords = 'windows python',
    url = '',
    packages = ['windows',
                'windows.generated_def',
                'windows.native_exec',
                'windows.utils',
                'windows.winobject',
                'windows.test'],
)