icebreaker
------
Break the ice with that cute Active Directory environment over there. Automates network attacks against Active Directory to deliver you plaintext credentials when you're inside the network but outside of the Active Directory environment. Performs 5 different network attacks for plaintext credentials as well as hashes. Autocracks hashes found with JohnTheRipper and a custom 1 million password wordlist specifically for Active Directory passwords.

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
  * Uses ntlmrelay.py and Responder.py to relay SMB hashes
  * After a successful relay it will do the following on the victim machine:
    * Add an administrative user - icebreaker:P@ssword123456
    * Run an obfuscated and AMSI bypassing version of Mimikatz and parse the output for hashes and passwords
* IPv6 DNS poison
  * Uses mitm6 and ntlmrelayx.py to poison IPv6 DNS and capture user and machine hashes
  * Creates fake WPAD server with authentication
  * Note: this can easily cause network connectivity issues for users so use sparingly


#### How It Works
It will perform the above 5 network attacks in order. RID cycling and SCF file uploads usually go fast, then it lingers on attack 3, Responder.py, for 10 min by default. After that amount of time, or the user-specified amount of time has passed, it will move on to the final two attacks which are run in parallel and indefinitely. 

After performing RID cycling and an asynchronous bruteforce it moves on to upload SCF files to anonymously writeable shares. If an SCF file was successfully uploaded and a user visits that file share in Explorer the user's hash will be captured and attempted to be cracked by icebreaker. If attack 3, LLMNR poisoning via Responder, is running when this occurs then the hash is simply captured and cracked. If attack 4, SMB relay via ntlmrelayx, is running, then this hash will be relayed to other machines in the network which do not have SMB signing enabled. Relaying a hash to another machine allows us to impersonate the user whose hash we captured and if that user has administrative rights to the machine we relayed the hash to then we can perform command execution.

Once ntlmrelayx relays a captured hash it will run a base64-encoded powershell command that first adds an administrative user (icebreaker:P@ssword123456) then runs an obfuscated and AMSI-bypassing version of Mimikatz. This mimikatz output is parsed and delivered to the user in the standard output as well as in the found-passwords.txt file. 

If icebreaker is run with the --auto flag, then upon reaching attack 4 icebreaker will run [Empire][https://www.powershellempire.com/] and [DeathStar](https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html) in xterm windows. With this option instead of running mimikatz on the remote box that we relayed the hash to, icebreaker will still add an administrative user but right after that it'll run Empire's powershell launcher code to get an agent on the remote machine. DeathStar will use this agent to automate the process of acheiving domain admin. The Empire and DeathStar xterm windows will not close when you exit icebreaker.

#### Installation
As root:
```
./setup.sh
pipenv shell
```

#### Usage
Run as root.
Read from a newline separated list of IP addresses (single IPs or CIDR ranges) and instead of having ntlmrelayx add a user and mimikatz the victim upon hash relay, have it execute a custom command on the victim machine. 

```./icebreaker -l targets.txt -c "net user /add User1 P@ssw0rd"```

Read from Nmap XML file and tell Responder to use the eth0 interface rather than the default gateway interface

```./icebreaker -x nmapscan.xml -i eth0```

Skip all five attacks and don't autocrack hashes

```./icebreaker.py -x nmapscan.xml -s rid,scf,llmnr,ntlmrelay,dns,crack```

Run attack 3, LLMNR poisoning, for 30 minutes before moving on to attack 4, SMB relaying

```./icebreaker.py -x nmapscan.xml -t 30```

Run Empire and DeathStar to automatically get domain admin after a successful hash relay via attacks 4 and 5

```./icebreaker.py -x nmapscan.xml --auto```
