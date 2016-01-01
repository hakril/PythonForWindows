# PythonForWindows

PythonForWindows is a base of code aimed to make interaction with Windows (on X86/X64) easier (with both 32 and 64 bits Python).
It's goal is to offer abstractions around some of the OS features in a (I hope) pythonic way.
It also tries to make the barrier between python and native execution thiner in both ways.
There is no external dependencies but it relies heavily on the ctypes modules.


Some of this code is clean (IMHO) and some parts are just a wreck that work for now.
Let say that the codebase evolves with my needs and my curiosity.

You can find some examples of code in the `sample/` directory.

## Overview

### Processes / Threads

PythonForWindows offer a object oriented around processes of the system and allow you to:
    - Retrieve basic process informations (pid, name, ppid, bitness, ...)
    - Perform basic interprocess operation (alloc, create thread, read/write memory)
    - Explore the PEB (Process Environment Block)
    - Execute native and python code in the context of the process.
    
I try by best to make those features available for every cross-bitness processes (32 <-> 64 in both ways).
This involve relying on non-documented Windows function/behaviour and also injecting code in the 64bits world of a Syswow64 process.
All those operations are also available for the `current_process`.

You can also make some operation of threads (suspend/resume/wait/get( or set) context/ kill)


### IAT Hook

This codebase is born from my need to have IAT hooks implemented in Python.
So the features is present (see `sample`)


### Winproxy

A pythonic wrapper around some Windows functions. Arguments name and order are the same,
but some have default values and the functions raise exception on call error (I don't like 'if' around all my call).


### Native execution

To make the barrier beetwen native and python code,
PythonForWindows allows you to create native function callable from Python (thanks ctypes) and also embded
a simple x86/x64 assembler.


### COM on Python

Some code to call a COM interface from Python or create a COM object implemented in Python.


### Other stuff

Some code are just exploration and need improvement like:
    - Wintrust
    - WMI
    - Registry access
    - Exception

