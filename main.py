#!/usr/bin/env python3

import os
import json
import argparse

parser = argparse.ArgumentParser()

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
    parser.add_argument('-s', '--summary', help='Display summary of metrics')
    parser.add_argument('-v', '--verbose', action='store_true')
    args = parser.parse_args()

    print('[*] starting log analyzer...')
    load_logs(args.file)
    print('[+] log file loaded!')
    print('[*] generating reports...')

    intruders = successful_logins(data_set)
    ip_addresses = unique_ip_addresses(data_set)

    print(json.dumps(intruders))
    output_files(ip_addresses)
    return

'''
load the configure file and parse it into events
'''
def load_logs(path):
    with open(path, 'r') as log_file:
        for line in log_file:
            parsed_line = json.loads(line)
            data_set.append(parsed_line)
    return

'''
write reports to disk
'''
def output_files(ips):
    with open('ip_addresses.json', 'w') as ip_file:
        ip_file.write(json.dumps(ips))
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
def connection_frequency():
    pass

'''
    ENTRY
'''
main()
