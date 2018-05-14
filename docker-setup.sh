# python's backports module is weird and gets confused on namespacing when Python is installed a certain unknown way
# pipenv will fail to build virtualenv if Python or the environment or something is installed weird because 
# pew.py will attempt to import a backports function and fail even though the module is installed right in pip
# but if we just apt-get install python-backports-shutil-get-terminal-size then that solves the problem apparently
echo -e '\n[*] Running: apt-get install python3 python python-dev python3-dev python-pip smbclient xterm python-backports-shutil-get-terminal-size -y'
apt-get install libxml2-dev lib sudo python3-dev python-pip python3-pip tmux python-pip smbclient xterm libssl-dev python-backports-shutil-get-terminal-size build-essential -y

echo -e '\n[*] Running: pip2 install pexpect mitm6 ldap3'
pip2 install --upgrade mitm6 m2crypto pexpect ldap3

pip3 install --upgrade netaddr asyncio python-libnmap netifaces requests termcolor libtmux

#echo -e '\n[*] Running: rm submodules/Responder/Responder.db'
#rm submodules/Responder/Responder.db

echo -e '\n[*] Running: git submodule update  --init --recursive -j 7'
git submodule update --init --recursive -j 7

if [ ! -f submodules/JohnTheRipper/run/john ]; then
	echo -e '\n[*] Running: cd submodules/JohnTheRipper/src && ./configure && make'
	cd submodules/JohnTheRipper/src && ./configure && make
else
	cd submodules/JohnTheRipper/src
fi

echo -e '\n[*] Running: cd ../../impacket/'
cd ../../impacket/

echo -e '\n[*] Running: python2 setup.py install'
python2 setup.py install

echo -e '\n[*] Running: cd ../Empire/setup/'
cd ../Empire/setup/

echo -e '\n[*] Running: yes | ./install.sh'
yes | ./install.sh

echo -e '\n[*] Running: cd ../../../'
cd ../../../
