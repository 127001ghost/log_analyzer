#!/usr/bin/env python3
'''
127001ghost
cowrie log analyzer
v0.1.1
'''

import os
import json
import argparse
import requests

'''
class to store reports
'''
class Store():
    def __init__(self):
        self.output_path            = 'output'
        self.verbose                = False
        self.remove_tor_addresses   = False

        self.events                 = list()
        self.successful_logins      = list()
        self.ip_addresses           = list()
        self.repeated_connections   = dict()
        self.credentials            = dict()
        self.tor_addresses          = list()
        self.tcp_data               = dict()


###################################################
#                    MAIN
###################################################
def main():
    # setup arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Relative path of log file', required=True)
    parser.add_argument('-s', '--summary', help='Display summary of metrics', action='store_true')
    parser.add_argument('-v', '--verbose', help='Verbose output', action='store_true')
    parser.add_argument('-o', '--output', help='Path of output destination. Default is ./output', type=str)
    parser.add_argument('-dt', '--detect-tor', help='Detect tor ip addresses', action='store_true')
    args = parser.parse_args()

    # initialize the store
    store = Store()

    if args.verbose:
        store.verbose = True
    if args.output:
        print(args.output)
        store.output_path = args.output
    if args.detect_tor:
        answer = input('[!] detecting tor ips will make 2 http requests! do you wish to continue? (y/n) ')
        if answer.lower() == 'n':
            exit(0)
        answer = input('[!] would you like to remove tor addresses from the ip report? (y/n) ')
        if answer.lower() == 'y':
            store.remove_tor_addresses = True

    print('[*] starting analyzer...')

    # load and parse the log file
    load_logs(store, args.file)

    if store.verbose:
        print('[+] logs loaded!')
        print('[*] parsing events...')

    # loop through eventids
    for event in store.events:
        if event['eventid'] == 'cowrie.login.success':
            event_login_success(store, event)
        if event['eventid'] == 'cowrie.log.closed':
            event_log_closed(store, event)
        if event['eventid'] == 'cowrie.session.closed':
            event_session_closed(store, event)
        if event['eventid'] == 'cowrie.session.file_upload':
            event_file_upload(store, event)
        if event['eventid'] == 'cowrie.command.input':
            event_command_input(store, event)

    if store.verbose:
        print('[+] all events parsed!')

    if args.detect_tor:
        detect_tor_addresses(store)

    write_reports(store)

    if args.summary:
        display_summary(store)
    print('[+] completed!')
    return


###################################################
#                EVENT HANDLING
###################################################
'''
handle 'cowire.login.success'
'''
def event_login_success(store, event):
    source_ip = event['src_ip']

    # add a new login
    store.successful_logins.append({
        'ip_address':       event['src_ip'],
        'login_timestamp':  event['timestamp'],
        'session_id':       event['session'],
        'username':         event['username'],
        'password':         event['password']
    })

    # add ip to list
    if source_ip not in store.ip_addresses:
        store.ip_addresses.append(source_ip)

    # add credentials to list
    if source_ip not in store.credentials:
        store.credentials[source_ip] = [f"{event['username']} :: {event['password']}"]
    else:
        store.credentials[source_ip].append(f"{event['username']} :: {event['password']}")

    # check for repeat connection
    if source_ip not in store.repeated_connections:
        store.repeated_connections[source_ip] = 1
    else:
        store.repeated_connections[source_ip] = store.repeated_connections[source_ip] + 1

    return

'''
handle 'cowrie.log.closed'
'''
def event_log_closed(store, event):
    for login in store.successful_logins:
        if login['session_id'] == event['session']:
            login['log_file'] = event['ttylog']
    return

'''
handle 'cowrie.session.closed'
'''
def event_session_closed(store, event):
    for login in store.successful_logins:
        if login['session_id'] == event['session']:
            login['exit_timestamp'] = event['timestamp']
            login['duration'] = event['duration']
    return

'''
handle 'cowrie.file.upload'
'''
def event_file_upload(store, event):
    for login in store.successful_logins:
        if login['session_id'] == event['session']:
            login['file_uploaded'] = event['filename']
            login['outfile'] = event['outfile']
    return

'''
handle 'cowrie.command.input'
'''
def event_command_input(store, event):
    for login in store.successful_logins:
        if login['session_id'] == event['session']:
            if 'commands' in login:
                login['commands'].append(event['input'])
            else:
                login['commands'] = [ event['input'] ]
    return


####################################################
#                   MISC
####################################################
def load_logs(store, file_path):
    if store.verbose:
        print('[*] loading logs...')
    try:
        with open(file_path, 'r') as log_file:
            for line in log_file:
                store.events.append(json.loads(line))
    except:
        print('[!] error while loading logs!')
        exit(1)
    return

def write_reports(store):
    if store.verbose:
        print('[*] writing logs to disk...')
    try:
        if not os.path.exists(store.output_path):
            os.makedirs(store.output_path)

        with open(store.output_path + '/ip_addresses.json', 'w') as ip_file:
            ip_file.write(json.dumps(store.ip_addresses))
        with open(store.output_path + '/successful_logins.json', 'w') as login_file:
            login_file.write(json.dumps(store.successful_logins))
        with open(store.output_path + '/credentials.json', 'w') as credential_file:
            credential_file.write(json.dumps(store.credentials))
        with open(store.output_path + '/repeated_connections.json', 'w') as repeat_file:
            repeat_file.write(json.dumps(store.repeated_connections))
        with open(store.output_path + '/tor_addresses.json', 'w') as tor_file:
            tor_file.write(json.dumps(store.tor_addresses))
    except Exception as ex:
        print(ex)
        print('[!] error writing files to disk!')
    return

def detect_tor_addresses(store):
    if store.verbose:
        print('[*] pulling tor addresses...')

    all_relay_nodes = requests.get('https://lists.fissionrelays.net/tor/relays-ipv4.txt')
    all_exit_nodes = requests.get('https://check.torproject.org/cgi-bin/TorBulkExitList.py')

    if all_exit_nodes.status_code != 200 or all_relay_nodes.status_code != 200:
        print('[!] error fetching tor lists!')
        return

    exit_nodes = all_exit_nodes.text
    relay_nodes = all_relay_nodes.text

    for ip in store.ip_addresses:
        if ip in exit_nodes or ip in relay_nodes:
            store.tor_addresses.append(ip)
            if store.remove_tor_addresses:
                store.ip_addresses.remove(ip)
    return

def display_summary(store):
    print('[+] -------------------------------------')
    print(f'[+] total # of ip addresses: {len(store.ip_addresses)}')
    print(f'[+] total # of successful logins: {len(store.successful_logins)}')
    print(f'[+] total # of tor users: {len(store.tor_addresses)}')
    print('[+] -------------------------------------')
    return


####################################################
#                   ENTRY
####################################################
if __name__ == '__main__':
    main()
