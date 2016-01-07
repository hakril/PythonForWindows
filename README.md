# PythonForWindows

PythonForWindows is a base of code aimed to make interaction with `Windows` (on X86/X64) easier (for both 32 and 64 bits Python).
Its goal is to offer abstractions around some of the OS features in a (I hope) pythonic way.
It also tries to make the barrier between python and native execution thinner in both ways.
There is no external dependencies but it relies heavily on the `ctypes` module.


Some of this code is clean (IMHO) and some parts are just a wreck that works for now.
Let's say that the codebase evolves with my needs and my curiosity.

Complete online documentation is available [here][ONLINE_DOC]
You can find some examples of code in the [samples directory][SAMPLE_DIR] or [online][ONLINE_SAMPLE].

Parts of PythonForWindows are used in the [LKD project][LKD_GITHUB].

## Overview

### Processes / Threads

PythonForWindows offers objects around processes and allows you to:

- Retrieve basic process informations (pid, name, ppid, bitness, ...)
- Perform basic interprocess operation (allocation, create thread, read/write memory)
- Explore the PEB (Process Environment Block)
- Execute `native` and `Python` code in the context of a process.

I try by best to make those features available for every cross-bitness processes (`32 <-> 64` in both ways).
This involve relying on non-documented `Windows` function/behaviour and also injecting code in the 64bits world of a `Syswow64` process.
All those operations are also available for the `current_process`.

You can also make some operation on threads (suspend/resume/wait/get(or set) context/ kill)


### IAT Hook

This codebase is born from my need to have IAT hooks implemented in Python.
So the features is present (see online documentation)


### Winproxy

A wrapper around some Windows functions. Arguments name and order are the same,
but some have default values and the functions raise exception on call error (I don't like 'if' around all my call).


### Native execution

To make the barrier between `native` and `Python` code,
PythonForWindows allows you to create native function callable from Python (thanks `ctypes`) and also embed
a simple x86/x64 assembler.


## Other stuff

Some code are just exploration and need improvement like:

- Wintrust
- WMI
- Exception
- COM


[LKD_GITHUB]: https://github.com/sogeti-esec-lab/LKD/
[SAMPLE_DIR]: https://github.com/hakril/PythonForWindows/tree/master/samples
[ONLINE_DOC]: http://hakril.github.io/PythonForWindows/
[ONLINE_SAMPLE]: http://hakril.github.io/PythonForWindows/sample.html