#!/usr/bin/env python3

import os
import json
import argparse
import requests

parser = argparse.ArgumentParser()

output_path = 'output'

data_set             = list()   # full data set
intruders            = list()   # successful connections
ip_addresses         = list()   # listof unique ips
connection_frequency = dict()   # dictionary of ip and # of connection attempts
credentials          = dict()   # dict of ip and the creds they tried
tor_ips              = list()   # detect tor ips

'''
    MAIN
'''
def main():
    # setup arguments
    parser.add_argument('-f', '--file', help='Relative path of the logfile', required=True)
    parser.add_argument('-g', '--geolocation', help='Get geolocation of ip. May take a while.', action='store_true')
    parser.add_argument('-s', '--summary', help='Display summary of metrics', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-dt', '--detect-tor', help='Check if ips are a tor exit node', action='store_true')

    # TODO: implement these
    parser.add_argument('-r', '--reports', help='Reports to generate', type=str)
    parser.add_argument('--ping-back', help='Ping IP addresses', action='store_true')
    parser.add_argument('--scan-back', help='Scan targets using Nmap', action='store_true')
    args = parser.parse_args()

    # confirm for functions that make http requests
    if args.geolocation:
        ans = input('[!] fetching geolocation may take a very long time, would you like to continue? (y/n) ')
        if ans == 'n' or ans == 'N':
            exit(0)
    if args.detect_tor:
        ans = input('[!] checking for tor addresses will make an http request! would you like to continue? (y/n) ')
        if ans.lower() == 'n':
            exit(0)

    print('[*] starting log analyzer...')
    load_logs(args.file)

    if args.verbose:
        print('[+] log file loaded!')
        print('[*] generating reports...')

    intruders = successful_logins(data_set)
    ip_addresses = unique_ip_addresses(data_set)
    credentials = used_credentials(data_set)
    tor_ips = detect_tor(ip_addresses)

    if args.geolocation:
        if args.verbose:
            print('[*] fetching geolocation...')
        ip_geolocation(data_set)

    if args.verbose:
        print('[*] writing files...')
    output_files(ip_addresses, intruders, credentials, tor_ips)

    if args.summary:
        print('[+] ----------------------------------------')
        print(f'[+] total # of ips: {len(ip_addresses)}')
        print(f'[+] total # of successful logins: {len(intruders)}')
        print(f'[+] total # of tor hits: {len(tor_ips)}')
        print('[+] ----------------------------------------')
    print('[+] completed!')
    return

'''
load the configure file and parse it into events
'''
def load_logs(path):
    try:
        with open(path, 'r') as log_file:
            for line in log_file:
                parsed_line = json.loads(line)
                data_set.append(parsed_line)
    except:
        print('[!] something went wrong in load_logs!')
        exit(1)
    return

'''
write reports to disk
'''
def output_files(ips, intruders_list, cred_list, tor_list):
    try:
        # create dir if not exists
        if not os.path.exists(output_path):
            os.makedirs(output_path)

        with open(output_path + '/ip_addresses.json', 'w') as ip_file:
            ip_file.write(json.dumps(ips))
        with open(output_path + '/intrusions.json', 'w') as intrusions:
            intrusions.write(json.dumps(intruders_list))
        with open(output_path + '/credentials.json', 'w') as creds:
            creds.write(json.dumps(cred_list))
        with open(output_path + '/tor_ips.json', 'w') as tor_file:
            tor_file.write(json.dumps(tor_list))
    except:
        print('[!] something went wrong in output_files!')
    return

'''
this method will generate a list of successful logins.

the structure will look like this:
{
    'ip_address': string,
    'login_timestamp': string
    'session_id': string
    'creds'; string
    'log_file': string
    'commands': [string]
}
'''
def successful_logins(events):
    logins = list()
    for event in events:
        # check for successful logins
        if event['eventid'] == 'cowrie.login.success':
            logins.append({
                'ip_address': event['src_ip'],
                'login_timestamp': event['timestamp'],
                'session_id': event['session'],
                'username': event['username'],
                'password': event['password']
            })

        # check for completed log files
        if event['eventid'] == 'cowrie.log.closed':
            for index, intruder in enumerate(logins):
                if logins[index]['session_id'] == event['session']:
                    logins[index] = { **logins[index], 'log_file': event['ttylog'] }

        # check session for commands
        if event['eventid'] == 'cowrie.command.input':
            for index, intruder in enumerate(logins):
                if 'commands' in logins[index] and logins[index]['session_id'] == event['session']:
                    logins[index]['commands'].append(event['input'])
                elif 'commands' not in logins[index] and logins[index]['session_id'] == event['session']:
                    logins[index]['commands'] = [event['input']]

        # check for logout times and duration
        if event['eventid'] == 'cowrie.session.closed':
            for index, intruder in enumerate(logins):
                if logins[index]['session_id'] == event['session']:
                    logins[index]['exit_timestamp'] = event['timestamp']
                    logins[index]['duration'] = event['duration']
    return logins

'''
generate a list of the unique ip addresses
'''
def unique_ip_addresses(events):
    ips = list()
    for event in events:
        if event['src_ip'] not in ips:
            ips.append(event['src_ip'])
    return ips

'''
get country name based on ip
'''
def ip_geolocation():
    pass

'''
this will generate a dictionary containing each ip address and how many times
they tried to connect.

{
    'ip': int
}
'''
def connection_frequency(events):
    for event in events:
        if event['src_ip'] not in connection_frequency:
            print('not implemented')
    pass

'''
make associations with ip and creds
should create a list like this:
ip: ['username:password', 'username:password']
'''
def used_credentials(events):
    creds = dict()
    for event in events:
        if event['eventid'] == 'cowrie.login.success':
            if event['src_ip'] in creds:
                creds[event['src_ip']].append(f"{event['username']}:{event['password']}")
            else:
                creds[event['src_ip']] = [f"{event['username']}:{event['password']}"]
    return creds

'''
detect if an ip address is a tor node
'''
def detect_tor(ip_list):
    tor_nodes = list()
    all_tor_exit_nodes = requests.get('https://check.torproject.org/cgi-bin/TorBulkExitList.py')
    all_tor_relay_nodes = requests.get('https://lists.fissionrelays.net/tor/relays-ipv4.txt')

    if all_tor_exit_nodes.status_code != 200 or all_tor_relay_nodes.status_code != 200:
        print('[!] error while checking the tor list!')
        return

    exit_nodes = all_tor_exit_nodes.text
    relay_nodes = all_tor_relay_nodes.text
    for ip in ip_list:
        if ip in exit_nodes:
            tor_nodes.append(ip)
        elif ip in relay_nodes:
            tor_nodes.append(ip)
    return tor_nodes

'''
ping addresses in the list of ips and determine which ones are up
'''
def ping():
    pass

'''
run an nmap stealth scan on targets
'''
def scan_ip():
    pass

'''
    ENTRY
'''
main()
