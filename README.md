# Zeratool
Automatic Exploit Generation (AEG) and remote flag capture for exploitable CTF problems

This tool uses [angr](https://github.com/angr/angr) to concolically analyze binaries by hooking printf and looking for [unconstrained paths](https://github.com/angr/angr-doc/blob/master/docs/examples.md#vulnerability-discovery). These program states are then weaponized for remote code execution through [pwntools](https://github.com/Gallopsled/pwntools) and a series of script tricks. Finally the payload is tested locally then submitted to a remote CTF server to recover the flag.

[![asciicast](https://asciinema.org/a/188002.png)](https://asciinema.org/a/188002)

## Installing
Zeratool has been tested on Ubuntu 16.04 and the install script is setup for Ubuntu 12.04 to Ubuntu 18.04

    ./install.sh
    
## Usage
Zeratool is a python script which accept a binary as an argument and optionally a linked libc library, and a CTF Server connection information

```
[chris:~/Zeratool] [angr] python zeratool.py -h
usage: zeratool.py [-h] [-l LIBC] [-u URL] [-p PORT] [-v] file

positional arguments:
  file                  File to analyze

optional arguments:
  -h, --help            show this help message and exit
  -l LIBC, --libc LIBC  libc to use
  -u URL, --url URL     Remote URL to pwn
  -p PORT, --port PORT  Remote port to pwn
  -v, --verbose         Verbose mode
```

## Exploit Types
Zeratool is designed around weaponizing buffer overflows and format string vulnerabilities and currently supports a couple types:

 * Buffer Overflow
   * Point program counter to win function
   * Point program counter to shellcode
   * Point program counter to rop chain
     * Rop chains need a libc base address
     * one-gadget and ropper are used rop chain building
 * Format String
   * Point GOT entry to win function
   * Point GOT entry to shellcode

Zeratool has room to grow and future iterations of Zeratool will include information disclosure discovery and linking those leaks to an offset for general ASLR bypasses. 

## Examples
Checkout the samples.sh file. The file contains several examples of Zeratool automatically solving exploitable CTF problems.

[Long Asciinema with Three Solves](https://asciinema.org/a/188001)

```
#!/bin/bash
#Buffer Overflows with win functions
python zeratool.py challenges/ret -u ctf.hackucf.org -p 9003
python zeratool.py challenges/bof3 -u ctf.hackucf.org -p 9002
python zeratool.py challenges/bof2 -u ctf.hackucf.org -p 9001
python zeratool.py challenges/bof1 -u ctf.hackucf.org -p 9000

#Down for the summer
#python zeratool.py challenges/easy_format -u tctf.competitivecyber.club -p 7801
#python zeratool.py challenges/medium_format -u tctf.competitivecyber.club -p 7802

#Format string leak
python zeratool.py challenges/easy_format
#Format string point to win function
python zeratool.py challenges/medium_format
#Format string point to shellcode
python zeratool.py challenges/hard_format #This one sometimes needs to be run twice

#Buffer overflow point to shellcode
python zeratool.py challenges/demo_bin
```

## FAQ
Q. Why doesn't Zeratool work against my simple exploitable?

A. Zeratool is held together by scotch tape and dreams. 
