# Zeratool v2.2
Automatic Exploit Generation (AEG) and remote flag capture for exploitable CTF problems

This tool uses [angr](https://github.com/angr/angr) to concolically analyze binaries by hooking printf and looking for [unconstrained paths](https://github.com/angr/angr-doc/blob/master/docs/examples.md#vulnerability-discovery). These program states are then weaponized for remote code execution through [pwntools](https://github.com/Gallopsled/pwntools) and a series of script tricks. Finally the payload is tested locally then submitted to a remote CTF server to recover the flag.

[![asciicast](https://asciinema.org/a/457964.svg)](https://asciinema.org/a/457964)

## Version 2.2 changes

Zeratool now supports remote libc leaking with buffer overflows. When a `puts` or `printf` call is present, Zeratool will leak out remote GOT entries and submit them to an online libc searching database to find offsets without the need for a local copy of the library.

[See remote libc leak in action!](https://asciinema.org/a/LL2ASZkIwEdwR0xsnzMb3oFLp)

Zeratool supports some basic ret2dlresolve chaining for 64bit binaries. See the example below on how to run it.

## Version 2.1 changes

Zeratool now supports some smart rop chain generation. During a buffer overflow
Zeratool will attempt to leak a libc address and compute the base address and build a execve(/bin/sh,NULL,NULL) chain or system(/bin/sh) chain.

## Installing
Zeratool has been tested on Ubuntu 16.04 through 20.04. Please install [radare2](https://github.com/radareorg/radare2) first

    pip install zeratool
    
## Usage
Zeratool is a python script which accept a binary as an argument and optionally a linked libc library, and a CTF Server connection information

```
[chris:~/Zeratool] zerapwn.py -h
usage: zerapwn.py [-h] [-l LIBC] [-u URL] [-p PORT] [-v] [--force_shellcode] [--force_dlresolve] [--skip_check] [--no_win] [--format_only] [--overflow_only] file

positional arguments:
  file                  File to analyze

optional arguments:
  -h, --help            show this help message and exit
  -l LIBC, --libc LIBC  libc to use
  -u URL, --url URL     Remote URL to pwn
  -p PORT, --port PORT  Remote port to pwn
  -v, --verbose         Verbose mode
  --force_shellcode     Set overflow pwn mode to point to shellcode
  --force_dlresolve     Set overflow pwn mode to use ret2dlresolve
  --skip_check          Skip first check and jump right to exploiting
  --no_win              Skip win function checking
  --format_only         Only run format strings check
  --overflow_only       Only run overflow check

```

## Exploit Types
Zeratool is designed around weaponizing buffer overflows and format string vulnerabilities and currently supports a couple types:

 * Buffer Overflow
   * Point program counter to win function
   * Point program counter to shellcode
   * Point program counter to rop chain
     * Rop chains will attempt to leak a libc function
     * Rop chains will then execve(/bin/sh) or system(/bin/sh)
     * Can attempt a ret2dlresolve ropchain
     * Can attempt to use puts/printf to leak remote libc
 * Format String
   * Point GOT entry to win function
   * Point GOT entry to shellcode

## Examples
Checkout the samples.sh file. The file contains several examples of Zeratool automatically solving exploitable CTF problems.


```
#!/bin/bash
# Buffer Overflows with win functions
zerapwn.py tests/bin/bof_win_32
zerapwn.py tests/bin/bof_win_64
# Buffer Overflows with ropping
zerapwn.py tests/bin/bof_nx_32
zerapwn.py tests/bin/bof_nx_64
# Buffer Overflow with ropping and libc leak
zerapwn.py tests/bin/bof_nx_64 -l tests/bin/libc.so.6_amd64

#Format string leak
zerapwn.py tests/bin/read_stack_32
zerapwn.py tests/bin/read_stack_64
#Format string point to win function
zerapwn.py challenges/medium_format
#Format string point to shellcode
#zerapwn.py challenges/hard_format #This one sometimes needs to be run twice

# Buffer overflow point to shellcode
# Turn off aslr 
# echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
zerapwn.py tests/bin/bof_32 --force_shellcode
zerapwn.py tests/bin/bof_64 --force_shellcode

# Remote libc leak
socat TCP4-LISTEN:7903,tcpwrap=script,reuseaddr,fork EXEC:./bof_nx_64
zerapwn.py tests/bin/bof_nx_64 -u localhost -p 7903 --skip_check --overflow_only

# Ret2dlresolve
zerapwn.py tests/bin/bof_dlresolve_64 --force_dlresolve --skip_check --overflow_only --no_win
```

[Long Asciinema with Three Solves](https://asciinema.org/a/188001)

## Run the tests!
Tox and Pytest are used to verify that Zeratool is working correctly.
```
tox .
```

## FAQ
Q. Why doesn't Zeratool work against my simple exploitable?

A. Zeratool is held together by scotch tape and dreams. 
