#!/usr/bin/env python3

import os
import json
import argparse

parser = argparse.ArgumentParser()

output_path = 'output/'

data_set             = list()   # full data set
intruders            = list()   # successful connections
ip_addresses         = list()   # listof unique ips
connection_frequency = dict()   # dictionary of ip and # of connection attempts

'''
    MAIN
'''
def main():
    # setup arguments
    parser.add_argument('-f', '--file', help='Relative path of the logfile', required=True)
    parser.add_argument('-g', '--geolocation', help='Get geolocation of ip. May take a while.', action='store_true')
    parser.add_argument('-s', '--summary', help='Display summary of metrics', action='store_true')
    parser.add_argument('-v', '--verbose', action='store_true')

    # TODO: implement these
    parser.add_argument('-r', '--reports', help='Reports to generate', type=str)
    parser.add_argument('--ping-back', help='Ping IP addresses', action='store_true')
    parser.add_argument('--scan-back', help='Scan targets using Nmap', action='store_true')
    args = parser.parse_args()

    if args.geolocation:
        ans = input('[!] fetching geolocation may take a very long time, would you like to continue? (y/n) ')
        if ans == 'n' or ans == 'N':
            # might be better to just switch the flag to false and continue
            exit(0)

    print('[*] starting log analyzer...')
    load_logs(args.file)

    if args.verbose:
        print('[+] log file loaded!')
        print('[*] generating reports...')

    intruders = successful_logins(data_set)
    ip_addresses = unique_ip_addresses(data_set)

    if args.geolocation:
        if args.verbose:
            print('[*] fetching geolocation...')
        ip_geolocation(data_set)

    if args.verbose:
        print('[*] writing files...')
    output_files(ip_addresses, intruders)

    if args.summary:
        print('[+] ----------------------------------------')
        print(f'[+] total # of ips: {len(ip_addresses)}')
        print(f'[+] total # of successful logins: {len(intruders)}')
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
def output_files(ips, intruders_list):
    try:
        with open(output_path + 'ip_addresses.json', 'w') as ip_file:
            ip_file.write(json.dumps(ips))
        with open(output_path + 'intrusions.json', 'w') as intrusions:
            intrusions.write(json.dumps(intruders_list))
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
                if 'commands' in logins[index]:
                    logins[index]['commands'].append(event['input'])
                else:
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
    pass

'''
    ENTRY
'''
main()
