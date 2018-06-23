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
#Sometimes r2 debug doesn't give us matching shellcode
#locations to our normal running environment. and sometimes
#running it twice makes it work
python zeratool.py challenges/hard_format 

#Buffer overflow point to shellcode
python zeratool.py challenges/demo_bin
