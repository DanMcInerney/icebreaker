echo -e '\n[*] Running: apt-get install python3-dev python-pip libssl-dev -y'
apt-get install python3-dev python-pip libssl-dev smbclient -y

echo -e '\n[*] Running: pip install pipenv pexpect'
pip install pipenv

echo -e '\n[*] Running: git submodule init'
git submodule init

echo -e '\n[*] Running: git submodule update --recursive'
git submodule update --recursive

if [ ! -f submodules/JohnTheRipper/run/john ]; then
	echo -e '\n[*] Running: cd submodules/JohnTheRipper/src && ./configure && make'
	cd submodules/JohnTheRipper/src && ./configure && make
fi

echo -e '\n[*] Running: cd ../../impacket/'
cd ../../impacket/

echo -e '\n[*] Running: python2 setup.py install'
python2 setup.py install

echo -e '\n[*] Running: pip2 install ldap3'
pip2 install ldap3

echo -e '\n[*] Running: pipenv install --three'
pipenv install --three

echo -e '\n[*] KALI USERS: run "apt-get remove python-impacket" before running icebreaker'
echo -e '[*] Run "pipenv shell" before running icebreaker'
echo -e '[*] Example usage: ./icebreaker.py -l targets.txt'
