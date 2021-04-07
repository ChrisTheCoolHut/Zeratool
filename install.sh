#!/bin/bash
sudo apt-get install python-pip build-essential rubygems-integration ruby-dev rubygems python-dev libffi-dev pkg-config wget -y
#Ubuntu 12 -> rubygems
#Ubuntu 14 -> rubygems-integration
#Ubuntu 16,18 -> ruby-dev

sudo dpkg --add-architecture i386
sudo apt-get update
sudo apt-get install libc6:i386 libstdc++6:i386 -y

sudo pip install --upgrade pip==19.0.0 

sudo pip install virtualenv virtualenvwrapper
  
printf '\n%s\n%s\n%s' '# virtualenv' 'export WORKON_HOME=~/virtualenvs' 'source /usr/local/bin/virtualenvwrapper.sh' >> ~/.bashrc

export WORKON_HOME=~/virtualenvs
source /usr/local/bin/virtualenvwrapper.sh
 
mkvirtualenv zeratool

workon zeratool

sudo gem install one_gadget

#Need to port to latest angr
pip install angr==7.8.2.21 pwntools==3.13.0 ropper==1.13.6 cffi==1.7.0 future==0.16.0 pycparser==2.18  IPython==5.0 r2pipe==1.4.2 psutil==5.8.0 timeout_decorator==0.5.0

git clone https://github.com/radare/radare2.git

cd radare2
git checkout 5.1.0
sudo ./sys/install.sh

echo "####################"
echo "run: . ~/.bashrc"
echo "run: workon zeratool"
