echo '\n[*] Running: apt-get install python3-dev python-pip libssl-dev -y'
apt-get install python3-dev python-pip libssl-dev smbclient -y
echo '\n[*] Running: pip install pipenv'
pip install pipenv
echo '\n[*] Running: git submodule init'
git submodule init
echo '\n[*] Running: git submodule update --recursive'
git submodule update --recursive
echo '\n[*] Running: cd submodules/JohnTheRipper/src && ./configure && make'
cd submodules/JohnTheRipper/src && ./configure && make
echo '\n[*] Running: cd ../../impacket/'
cd ../../impacket/
echo '\n[*] Running: python2 setup.py install'
python2 setup.py install
echo '\n[*] Running: pip2 install ldap3'
pip2 install ldap3
echo '\n[*] Running: pipenv install --three'
pipenv install --three
echo '\n[*] KALI USERS: run "apt-get remove python-impacket" before running icebreaker'
echo '\n[*] Run "pipenv shell" before running icebreaker'
echo '\n[*] Example usage: ./icebreaker.py -l targets.txt'
