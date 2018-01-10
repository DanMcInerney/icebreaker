icebreaker
------
Break the ice with that cute Active Directory environment over there. Automates network attacks against Active Directory to deliver you piping hot plaintext credentials when you're inside the network but outside of the Active Directory environment. Performs 4 different network attacks for plaintext credentials as well as hashes. Autocracks hashes found with JohnTheRipper and the top 10 million most common passwords.

* RID cycling 
  * Uses Nmap to find NULL SMB sessions
  * Performs asynchronous RID cycling to find valid usernames
  * Performs a 2 password reverse bruteforce of found usernames
  * Passwords tested: P@ssw0rd and \<season\>\<year\>, e.g., Winter2018
* SCF file upload
  * Uses Nmap to find anonymously writeable shares on the network
  * Writes an SCF file to the share with a file icon that points to your machine
  * When a user opens the share in Explorer their hash is sent to you
  * Autocracks the hash with john and top 10 million password list
* LLMNR/NBTNS/mDNS poisoning
  * Uses Responder.py to poison the layer 2 network and capture user hashes
  * Autocracks the hash with john and top 10 million password list
* SMB relay
  * Uses ntlmrelay.py + Responder.py to relay SMB hashes
  * After a successful relay it will do the following on the victim machine:
    * Add an administrative user - icebreaker:P@ssword123456
    * Run an obfuscated and AMSI bypassing version of Mimikatz and parse the output for hashes and passwords

#### Installation
```
sudo ./setup.sh
sudo pipenv shell

Note to Kali users: you will need to run 'apt-get remove python-impacket' after running the setup script
```

#### Usage
Read from a newline separated list of IP addresses

```sudo ./icebreaker -l targets.txt```

Read from Nmap XML file

```sudo ./icebreaker -x nmapscan.xml```

Skip all four attacks

```sudo ./icebreaker.py -x nmapscan.xml -s rid,scf,llmnr,ntlmrelay

Run attack 3, LLMNR poisoning, for 30 minutes before moving on to attack 4, SMB relaying

```sudo ./icebreaker.py -x nmapscan.xml -t 30```
