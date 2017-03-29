#!/usr/bin/env python

# Purge Red Hat Storage Console Nodes
# Copyright (C) 2017, Kyle Squizzato <ksquizza@redhat.com>

# Use this script to remove old information from Red Hat Storage Console Nodes
# The script will clear the console database and re-initialize the nodes
# See --help for usage, see README for more info

# ---

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import sys
import os
import dbus
import socket
import signal
import atexit
import argparse
import json
import paramiko
from shutil import rmtree
from subprocess import Popen, PIPE

"""
Terminal colors
"""
class colors:
    INFO = '\033[95m'       # purple
    OKBLUE = '\033[96m'     # cyan
    OKGREEN = '\033[92m'    # green
    WARNING = '\033[93m'    # yellow
    ERROR = '\033[91m'      # red
    ENDC = '\033[0m'        # white
    BOLD = '\033[1m'        # bold
    UNDERLINE = '\033[4m'   # underline

"""
Construct a message with the following syntax:
[STATE] Message contents
with optional colorization using the above colors class
"""
def print_message(message, state=None, color=None):
    # color should be a member of above colors class, ie. colors.OKGREEN
    if color == None:
        # if no color is supplied use white
        color = colors.ENDC
    else:
        # calls to this function must accept an item from the colors class
        # above only
        try:
            color = color
        except AttributeError:
            raise
    #uppercase it and left justify it so the state labels match up
    state = state.upper()
    constructed_state = color + ('[{0}]'.format(state))
    constructed_message = str(constructed_state).ljust(20) + colors.ENDC + message
    return constructed_message

pm = print_message

"""
Manage a given service using systemctl
Valid commands are: stop, start, restart
See: https://wiki.freedesktop.org/www/Software/systemd/dbus/ for more info
"""
def manage_service(command, service):
    # append grammar to commands for a messagestr
    if command == 'stop':
        command_name = command + 'ping'
        command_name2 = command + 'ped'
    else:
        command_name = command + 'ing'
        command_name2 = command + 'ed'
    # build a messagestr, for example: Stopping salt-minion service
    messagestr = command_name + ' ' + service + ' service'
    print pm(messagestr, 'info', colors.INFO)
    try:
        sysbus = dbus.SystemBus()
        systemd = sysbus.get_object('org.freedesktop.systemd1',
                                    '/org/freedesktop/systemd1')
        manager = dbus.Interface(systemd,
                                 'org.freedesktop.systemd1.Manager')
        valid = {'stop', 'start', 'restart'}
        if command == 'stop':
            job = manager.StopUnit('{0}.service'.format(service), 'fail')
        if command == 'start':
            job = manager.StartUnit('{0}.service'.format(service), 'replace')
        if command == 'restart':
            job = manager.RestartUnit('{0}.service'.format(service), 'fail')
        if not any(v in command for v in valid):
            print pm('An invalid command was passed to manage_service()',
                 'error',
                 colors.ERROR)
            sys.exit(1)
        print pm('{0} {1} service'.format(command_name2, service),
                 'done', colors.OKBLUE)
    except dbus.exceptions.DBusException:
        print pm('An issue occurred while attempting to {0} {1}'.format(command, service),
                 'error',
                 colors.ERROR)
        raise
        sys.exit(1)

"""
rm -rf a tree
Give an absolute path for directory
"""
def remove_dir(directory):
    try:
        print pm('Removing {0}'.format(directory), 'info', colors.INFO)
        rmtree(directory)
    except IOError as e:
        print pm(e, 'error', colors.ERROR)
    print pm('{0} removed'.format(directory), 'done', colors.OKBLUE)

"""
Remove files
Provide an absolutepath with wildcard, ie. '/home/foobar/files/*'
"""
def remove_files(files):
    try:
        print pm('Removing {0}'.format(files), 'info', colors.INFO)
        for fl in glob.glob(files):
            os.remove(fl)
    except IOError as e:
        print pm(e, 'error', colors.ERROR)

"""
Check for root, exit if non-root
"""
def need_root():
    if os.geteuid() != 0:
        print pm('Root privileges are required to run this script, please re-run \
with root to continue', 'error', colors.ERROR)
        sys.exit(1)

"""
Validate given hostname
"""
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

""" Yes or no prompting """
def yes_no(question):
    yes = 'yes-i-really-really-mean-it'
    no = set(['no','n'])
    prompt = " [yes-i-really-really-mean-it / No] "
    while True:
        print question + '?' + prompt
        choice = raw_input().lower()
        if choice == '':
            # If no choice is given, return no
            return False
        if choice in no:
            return False
        if choice == yes:
            return True
        else:
           print "\nPlease respond with 'yes-i-really-really-mean-it' or 'no'"

"""
Attempt to automatically generate a host list from /etc/salt/pki/master/minions
"""
def generate_hosts():
    print pm('Attempting to generate a list of hosts associated with this RHSC',
             'info', colors.INFO)
    # the names of the key files represent the FQDNs of each of the associated
    # nodes, so we'll use those to construct a host_list
    host_list = []
    try:
        for fl in os.listdir("/etc/salt/pki/master/minions"):
            host_list.append(fl)
    except OSError:
        print pm('Unable to automatically generate node list, no \
/etc/salt/pki/master/minions directory found, is RHSC installed here? \
Exiting now',
        'error',
        colors.ERROR)
        print pm ('Use the -n, --nodes flag with FQDNs to circumvent automated node list generation',
        'info',
        colors.INFO)
        sys.exit(1)
    return host_list

"""
Build a list of hosts from given comma-delimited hosts and run validation
on each of them
"""
def build_host_list(hosts):
    print pm('Building a list of hosts from --nodes flag input', 'info',
             colors.INFO)
    try:
        host_list = set(hosts.split(","))
        for each in host_list:
            if is_valid_hostname(each) == False:
                print pm('The provided host: {0} does not appear to be a valid \
    FQDN or IP address'.format(each), 'error', colors.ERROR)
                sys.exit(1)
    except AttributeError:
        # FIXME: What if there's only one host by the time we get to other
        # functions?  Probably need to just keep one host a list still
        host_list = hosts
        if is_valid_hostname(host_list) == False:
            print pm('The provided host: {0} does not appear to be a valid \
    FQDN or IP address'.format(each), 'error', colors.ERROR)
            sys.exit(1)
    return host_list

"""
Given a host_list, clean each storage node
"""
def clean_nodes(host_list):
    storage_clean_command = 'systemctl stop salt-minion ; rm -rf /etc/salt/pki/minion'
    for each in host_list:
        # We shouldn't need keyless ssh as it should already be configured if
        # RHSC had already been running/deployed
        # If keyless ssh doesn't work on nodes then we'll just ask users to
        # set it up manually
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.load_system_host_keys()
        print pm('Connecting to host: {0} to clean storage node configuration'.format(each),
                 'info', colors.INFO)
        try:
            ssh.connect(each,
                    username="root",
                    look_for_keys=True
                    )
            stdin, stdout, stderr = ssh.exec_command(storage_clean_command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                print pm('Successfully cleaned host: {0}'.format(each), 'done',
                     colors.OKBLUE)
            else:
                print pm('Error cleaning host: {0}: \
systemctl stop salt-minion; rm -rf /etc/salt/pki/minion exited with: \
{1}'.format(each, exit_status),
                     'error',
                     colors.ERROR)
                ssh.close()
                sys.exit(1)
            ssh.close()
            print pm('Cleaned host: {0}'.format(each), 'done',
                     colors.OKBLUE)
        except paramiko.ssh_exception.SSHException as e:
            if str(e) == 'No authentication methods available':
                print pm('Error establishing ssh connection to host: {0}!'.format(each),
                         'error', colors.ERROR)
                print pm('Passwordless ssh is *not* configured for this host, \
please configure passwordless ssh for root for each storage node then re-run \
rhscon-purge\nSee: https://access.redhat.com/node/705363/',
                         'error', colors.ERROR)
                client.close()
                sys.exit(1)
            else:
                print pm('Error establishing ssh connection to host: {0}'.format(each),
                     'error', colors.ERROR)
                raise
                sys.exit(1)

"""
Clean the mongodb
Uses a mongo shell script which drops storage, storage_nodes, storage_clusters,
skyring_utilization, cluster_summary, storage_logical_units, tasks,
block_devices
See dbcleaner.js for more info
"""
def clean_db(scriptfile):
    # Get db password from skyring.conf, skyring.conf is json
    try:
        with open('/etc/skyring/skyring.conf') as skyringconf:
            skyringconf = json.load(skyringconf)
            password = str(skyringconf["dbconfig"]["password"])
    except IOError:
        print pm('Unable to find /etc/skyring/skyring.conf, is skyring installed here? Exiting',
                 'error', colors.ERROR)
        sys.exit(1)
    # Run the mongo clean
    print pm('Cleaning RHSC database', 'info', colors.INFO)
    mongo_args = ["/usr/bin/mongo", "127.0.0.1:27017/skyring",
                  "-u", "admin",
                  "-p", "{}".format(password),
                  "<", "{}".format(scriptfile)]
    print pm('Database cleaned', 'done', colors.OKBLUE)
    # Clean salt-keys
    print pm('Removing salt-keys', 'info', colors.INFO)
    salt_args = ["/usr/bin/salt",
                 "-D"]
    print pm('Salt-keys removed', 'done', colors.OKBLUE)

"""
Bootstrap client agent(s)
"""
def bootstrap_nodes(host_list, server_fqdn):
    bootstrapCommand = 'systemctl start salt-minion ; curl {0}:8181/setup/agent | bash'.format(server_fqdn)
    # Reopen the ssh connection so we can connect to each host in the lineup
    for each in host_list:
        print pm('Reinitializing storage node: {0}'.format(each), 'info', colors.INFO)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(each,
                    username="root",
                    look_for_keys=True
                    )
        stdin, stdout, stderr = ssh.exec_command(bootstrapCommand)
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            print pm('Storage node: {0} initialized'.format(each),
                     'done', colors.OKBLUE)
        else:
            print pm('Unable to bootstrap host: {0}: -{1}'.format(each, exit_status),
                     'error', colors.ERROR)
            client.close()
            sys.exit(1)
    print pm('Client agents have been installed and configured but may take a few moments to appear in the RHCS Web UI',
             'done', colors.OKBLUE)

"""
exit handler
"""
def exit_handler():
    pass

"""
Super simple signal handler
"""
SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) \
    for n in dir(signal) if n.startswith('SIG') and '_' not in n )

def signal_handler(signum, frame, retries=0):
    print pm("Received signal: {0}({1})".format(SIGNALS_TO_NAMES_DICT[signum], signum),
             'warning', colors.WARNING)
    raise RuntimeError('Received signal: {0}({1})'.format(SIGNALS_TO_NAMES_DICT[signum], signum))
    sys.exit(signum)

def main():
    parser = argparse.ArgumentParser(description='Purge an existing Red Hat \
                                     Storage Console 2.0 configuration.  This \
                                     script should be ran on the offending \
                                     RHSC host. This script also \
                                     reinitializes the storage \
                                     nodes configured to use the RHSC host.')
    parser.add_argument("-n",
                        "--nodes",
                        dest="nodes",
                        help='Define a FQDN or list of comma-delimited FQDNs which \
                        currently serve as nodes in a cluster.  rhscon-purge \
                        will attempt to determine nodes associated with an RHSC \
                        automatically.  This option should only be used to \
                        specify additional nodes that need to be cleaned, that \
                        did not clean successfully following automated \
                        cleaning.')
    parser.add_argument("--no-node-clean",
                        dest="nonode_clean",
                        action='store_true',
                        help='Do not clean the storage nodes, only clean the \
                        local configuration from the RHSC node.')

    args = parser.parse_args()

    print(colors.BOLD + 'Starting Red Hat Storage Console purge...' + colors.ENDC)
    print pm('**ALL** existing data on this RHSC will be removed once the purge is complete.',
       'warning', colors.WARNING)
    choice = yes_no('Are you sure you wish to proceed')

    if choice == True:
        # proceed
        # Check to see how we need to generate a host_list
        if args.nodes != None:
            host_list = build_host_list(args.nodes)
        else:
            host_list = generate_hosts()

        # Steps based on guide from https://access.redhat.com/solutions/2944461
        # Stop skyring and salt-master on RHSC node (where script runs)
        manage_service('stop', 'skyring')
        manage_service('stop', 'salt-master')

        # On all given storage nodes, stop salt-minion services and remove salt-keys
        if args.nonode_clean != True:
            clean_nodes(host_list)
        else:
            # Don't clean if nonode_clean is set
            print pm('--no-node-clean is set, skipping storage node cleaning',
                     'skip', colors.WARNING)
            pass

        # Clean the mongodb on the RHSC node
        clean_db('dbcleaner.js')

        # Remove minions directories
        remove_dir('/etc/salt/pki/master/minions')

        # Start skyring and salt-master
        manage_service('start', 'skyring')
        manage_service('start', 'salt-master')

        # Bootstrap client agents
        if args.nonode_clean != True:
            # get hostname of RHSC server for setup-agent
            server = socket.gethostname()
            # bootstrap the nodes
            bootstrap_nodes(host_list, server)
        else:
            # Don't bootstrap if nonode_clean is set
            print pm('--no-node-clean is set, skipping storage node bootstrap',
                     'skip', colors.WARNING)
            pass

        # Print a completion message and exit
        print pm('Purge successful', 'complete', colors.OKGREEN)
        sys.exit(0)
    else:
        # do not proceed and exit out
        print pm('Cancelling purge due to user input', 'exit', colors.OKBLUE)
        sys.exit(0)

"""
Main
"""
if __name__ == '__main__':
    atexit.register(exit_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    sys.exit(main())
