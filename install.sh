#!/bin/bash
sudo apt-get install python-pip python-dev build-essential rubygems-integration ruby-dev rubygems python-dev libffi-dev -y
#Ubuntu 12 -> rubygems
#Ubuntu 14 -> rubygems-integration
#Ubuntu 16,18 -> ruby-dev

sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install libc6:i386 libstdc++6:i386 -y

 
sudo pip install virtualenv virtualenvwrapper
 
sudo pip install --upgrade pip
  
printf '\n%s\n%s\n%s' '# virtualenv' 'export WORKON_HOME=~/virtualenvs' 'source /usr/local/bin/virtualenvwrapper.sh' >> ~/.bashrc

export WORKON_HOME=~/virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
 
mkvirtualenv zeratool

workon zeratool

sudo gem install one_gadget

#Need to port to latest angr
pip install angr==7.8.2.21 ropper r2pipe IPython

git clone https://github.com/radare/radare2.git

sudo ./radare2/sys/install.sh

pip install IPython==5.0 r2pipe psutil timeout_decorator pwn

echo "####################"
echo "run: . ~/.bashrc"
echo "run: workon zeratool"
