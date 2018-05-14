# I haven't tested any of these except Kali
# libssl1.0-dev libxml2-dev zlib1g-dev are all required for Empire to install properly because its installer is broken on Kali
echo -e '\n[*] Running: apt-get update'
apt-get update 
# python's backports module is weird and gets confused on namespacing when Python is installed a certain unknown way
# pipenv will fail to build virtualenv if Python or the environment or something is installed weird because 
# pew.py will attempt to import a backports function and fail even though the module is installed right in pip
# but if we just apt-get install python-backports-shutil-get-terminal-size then that solves the problem apparently
echo -e '\n[*] Running: apt-get install python3 python python-dev lsb_release python3-dev python-pip smbclient xterm python-backports-shutil-get-terminal-size -y'
apt-get install libicu55 libxml2-dev lib sudo python3-dev tmux python-pip smbclient xterm libssl-dev python-backports-shutil-get-terminal-size build-essential -y

echo -e '\n[*] Running: pip2 install pexpect mitm6 ldap3'
pip2 install --upgrade mitm6 m2crypto pexpect ldap3

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
