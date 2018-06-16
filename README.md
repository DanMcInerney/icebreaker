# icebreaker

Break the ice with that cute Active Directory environment over there. When you're cold and alone staring in at an Active Directory party but don't possess even a single AD credential to join the fun, this tool's for you.

Sequentially automates 5 internal network attacks against Active Directory to deliver you plaintext credentials. Use the --auto option to automatically acquire domain admin privileges after gaining a foothold.

## Summary Details
The following attacks are performed sequentially until the fourth and fifth attacks which run in parallel and indefinitely.

* Reverse bruteforce
  * Automatically acquires a list of usernames and tests each one with two of the most common AD passwords (more than two attempts may trigger account lockout policies)
* Upload to network shares
  * Capture users' passwords with malicious file uploads to available network shares
* Poison broadcast network protocols
  * Uses common network protocols to trick users' computers into sending you passwords
* Man-in-the-middle SMB connections
  * Performs remote command execution against AD computers in order to gather passwords
* Poison IPv6 DNS
  * Exploits DNS to trick AD computers into sending their users' passwords to you

## Technical Details
All NetNTLMv2 hashes which are captured in the techniques below are autocracked with JohnTheRipper and an AD-specific password list of 1 million in length.

* Reverse bruteforce
  * Uses rpcclient to find hosts that accept null SMB sessions
  * Uses ridenum to find valid usernames via RID cycling on null SMB hosts
  * Can use theHarvester to gather additional potential usernames from a specified internet domain
  * Performs a 2 password reverse bruteforce of found usernames or you can specify a password list to use
  * Default passwords tested: P@ssw0rd and \<current_season\>\<year\>, e.g., Spring2018
* SCF upload
  * Uses Nmap to find anonymously writeable network shares via NSE script smb-enum-shares
  * Writes an SCF file to the share with a file icon path that points to your machine
  * When an AD user opens the share in File Explorer their NetNTLMv2 hash is sent to you
* LLMNR/NBTNS/mDNS poisoning
  * Uses Responder.py to poison the layer 2 broadcast/multicast network protocols (LLMNR, NBT-NS, mDNS) and capture NetNTLMv2 hashes
* SMB relay
  * Uses ntlmrelayx.py and Responder.py to relay SMB hashes
  * Uses Nmap to identify vulnerable relay targets via the NSE script smb-security-mode
  * Vulnerable targets will have SMBv1 enabled and SMB signing disabled
  * Successful relaying of a hash will result in the capture of a user's NetNTLMv2 hash which will be autocracked
  * If a user hash is relayed to a machine and that user is a local administrator, command execution will occur and the following will be remotely performed:
    * Add an administrative user - icebreaker:P@ssword123456
    * Run an obfuscated and AMSI bypassing version of Mimikatz
    * Mimikatz output is parsed for NTLM hashes and plaintext passwords
    * Run an obfuscated and AMSI bypassing version of Invoke-PowerDump for SAM hashes 
    * Output is parsed for NTLM hashes
* IPv6 DNS poison
  * Uses mitm6 and ntlmrelayx.py to poison IPv6 DNS in order to capture NetNTLMv2 user hashes
  * Creates fake WPAD server with authentication
  * IPv6 DNS is enabled by default in Active Directory environments
  * Note: this can cause network connectivity issues for users


#### How It Works
It will perform the above 5 network attacks in order. Reverse bruteforcing and SCF file uploads usually go pretty quick, then it lingers on attack 3, Responder.py, for 10 min by default. After that amount of time, or the user-specified amount of time has passed, it will move on to the final two attacks which are run in parallel and indefinitely. 

If any hosts are discovered to allow null SMB sessions, icebreaker will use ridenum to perform RID cycling for valid usernames. If you use the "-d <somedomain.com>" option, theHarvester will scrape any email addresses from the specified website. Any email usernames that are AD-compatible will be added to the reverse bruteforce username list. Icebreaker uses the asyncio library to perform the reverse bruteforce using the linux tool rpcclient using 10 async workers.

The SCF upload attack abuses Shell Command Files against anonymously writeable network shares. SCFs are files that can perform basic actions like showing the desktop or opening a File Explorer window. They have the curious property of allowing you to set its file icon to a network path. If you set this network path to your own machine, users who open the file share in File Explorer will automatically send their NetNTLMv2 password hash to you. Icebreaker uses the Nmap script smb-enum-shares to find anonymously writeable shares then automatically generates and uploads the payloaded SCF.

Attack 3 uses Responder.py to poison LLMNR, NBT-NS, and mDNS multicast/broadcast protocols. When users navigate to a nonexistent network path, Responder will tell them your attacker machine is the correct path. The user's NetNTLMv2 password hash is now yours. Responder will capture hashes sent via the SCF attack, but the next attack is generally more useful for capturing SCF hashes because it has the potential of using the hash for command execution.

SMB relay is an old network attack where attackers place themselves inbetween the SMB client and the SMB server. This allows attackers to capture and relay NetNTLMv2 hashes to hosts that have SMBv1 enabled and SMB signing disabled. ntlmrelayx.py from the Impacket library is used to relay while Responder.py is used to man-in-the-middle SMB connections. Should the SMB client user have administrative rights to any host on the network that has SMB signing disabled, ntlmrelayx.py will perform command execution on that host. 

Once ntlmrelayx relays a captured hash it will run a base64-encoded powershell command that first adds an administrative user (icebreaker:P@ssword123456) then runs an obfuscated and AMSI-bypassing version of Mimikatz, followed by an obfuscated and AMSI-bypassing version of Invoke-PowerDump. The output of Invoke-Mimikatz and Invoke-PowerDump is parsed for plaintext passwords or NTLM hashes and delivered to the user in the standard output as well as in the found-passwords.txt file. NTLM hashes, unlike NetNTLMv2 hashes, can be used just like a plaintext password for authentication to other AD hosts. The one caveat is that ever since Microsoft’s KB2871997 patch, only the builtin RID 500 local administrator account can be used in pass-the-hash attacks.

The final attack uses the tool mitm6 to perform a man-in-the-middle IPv6 DNS attack against the whole network. This forces hosts on the network to use the attacker's machine as their DNS server. Once set as their DNS server, the attacker serves malicious WPAD proxy setting files to the victims and gathers their NetNTLMv2 hashes. These hashes are relayed using ntlmrelayx.py for further remote code execution possibilities. One thing to note is that this attack is prone to causing issues on the network. It often causes certificate errors on client machines in the browser. It'll also likely slow the network down. The beauty of this attack, however, is that Windows AD environments are vulnerable by default.

If icebreaker is run with the --auto [tmux/xterm] flag, then upon reaching attack 4 icebreaker will run [Empire](https://www.powershellempire.com/) and [DeathStar](https://byt3bl33d3r.github.io/automating-the-empire-with-the-death-star-getting-domain-admin-with-a-push-of-a-button.html) in either a tmux session or xterm windows. With this option, instead of running mimikatz on the remote host that we relayed the hash to, icebreaker will add an administrative user then run Empire's powershell launcher code to get an agent on the remote machine. DeathStar will use this agent to automate the process of achieving domain admin. The Empire and DeathStar will not close when you exit icebreaker.

Password cracking is done with JohnTheRipper and a custom wordlist. The origin of this list is from the [merged.txt](https://github.com/danielmiessler/SecLists/blob/601038eb4ea18c97177b43a757286d3c8a815db8/Passwords/merged.txt.tar.gz) which is every password from the SecLists GitHub account combined. The wordlist was pruned and includes no passwords with: all lowercase, all uppercase, all symbols, less than 7 characters, more than 32 characters. These rules conform to the default Active Directory password requirements and brought the list from 20 million to just over 1 million which makes password cracking extremely fast.

#### Installation
As root:
```
./setup.sh
pipenv install --three
pipenv shell
```
You might get an error after running pipenv install. Update to a version of pipenv higher than 11.9.0 if that is the case. You can git clone pipenv from github and just ```apt-get remove python-pipenv && python setup.py install``` from within the folder.

### Docker Usage
Still a few bugs to work out with the docker image so this is likely to error for you but it's almost there. From the Git Repo:
```
docker build --rm -t danmcinerney/icebreaker .
docker run danmcinery/icebreaker
```
Or append the commands you'd normally add to icebreaker (don't forget to map volumes):
```
docker run -v $(pwd)/logs:/icebreaker/logs -v $(pwd)/hashes:/icebreaker/hashes -v $(pwd)/icebreaker-scan.xml:/icebreaker/icebreaker-scan.xml -v $(pwd)/submodules:/icebreaker/submodules -e PYTHONUNBUFFERED=0 danmcinerney/icebreaker -x icebreaker-scan.xml
```
**Note: You'll want to map ports for listeners with docker's `-p <host>:<container>` flag. 

#### Usage
Run as root.
Read from a newline separated list of IP addresses (single IPs or CIDR ranges) and instead of having ntlmrelayx add a user and mimikatz the victim upon hash relay, have it execute a custom command on the victim machine. In this example we're giving it a command similar to what Empire might give us for a powershell launcher one-liner.

```./icebreaker -l targets.txt -c "powershell -nop -w hidden -exec bypass -enc WwFk..."```

Read from a hostlist, tell Responder to use the eth0 interface rather than the default gateway interface, let Responder run for 30m instead of the usual 10m, and run the default ntlmrelayx post-relay commands to dump the SAM off the victim server.

```./icebreaker -l targets.txt -i eth0 -t 30 -c default```

Use an Nmap XML output file, skip all five attacks plus don't autocrack hashes, and use a custom password list for the reverse bruteforce attack (note that since this example is skipping attack 1 via '-s rid' the password list specified won't even get used; this is just used as an example) 

```./icebreaker.py -x nmapscan.xml -s rid,scf,llmnr,relay,dns,crack -p /home/user/password-list.txt```

Fire-and-forget usage: input targets file, scrape companydomain.com for email usernames to be added to the reverse bruteforce attack, skip mitm6's IPv6 DNS poisoning, and run Empire and DeathStar in either tmux or xterm windows once attack 4 starts in order to gain automated domain admin. The goal of this usage is to fire off the command Monday at 9am then go take a short, uninterrupted break until Friday at 4:30pm at which point we come back to a domain admin shell waiting for us. We skip attack 5 (mitm6) because it can sometimes cause network issues and we don't want angry clients interrupting our hard-earned break.


```./icebreaker.py -l targets.txt -d companydomain.com -s dns --auto [tmux/xterm]```

