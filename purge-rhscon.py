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

import subprocess
import dbus
import os
from shutil import rmtree

"""
Terminal colors
"""
class colors:
    INFO = '\033[95m'       # purple
    OKBLUE = '\033[94m'     # blue
    OKGREEN = '\033[92m'    # green
    WARNING = '\033[93m'    # yellow
    FAIL = '\033[91m'       # red
    ENDC = '\033[0m'        # white
    BOLD = '\033[1m'        # bold
    UNDERLINE = '\033[4m'   # underline

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

"""
Remove files
Provide an absolutepath with wildcard, ie. '/home/foobar/files/*'
"""
def remove_file(files):
    try:
        print pm('Removing {0}'.format(files), 'info', colors.INFO)
        for fl in glob.glob(files):
            os.remove(fl)
    except IOError as e:
        print pm(e, 'error', colors.ERROR)

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
        except AttributeError as e:
            raise
    # if no state is supplied just build message with provided color
    if state == None:
        state = ''Popen
    constructed_state = color + ('[{0}] '.format(state))
    constructed_message = constructed_state + colors.ENDC + str(message)
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
    else:
        command_name = command + 'ing'
    # build a messagestr, for example: Stopping salt-minion service
    messagestr = command_name + ' ' + service + ' service'
    print pm(messagestr, 'info', colors.INFO)
    try:
        sysbus = dbus.SystemBus()
        systemd = sysbus.get_object('org.freedesktop.systemd1',
                                    '/org/freedesktop/systemd1')
        manager = dbus.Interface(systemd,
                                 'org.freedesktop.systemd.Manager')
        if command == 'stop':
            job = manager.StopUnit('{0}.service'.format(service), 'fail')
        if command == 'start':
            job = manager.StartUnit('{0}.service'.format(service), 'fail')
        if command == 'restart':
            job = manager.RestartUnit('{0}.service'.format(service), 'fail')
        if not command == 'stop' or 'start' or 'restart':
            print pm('An invalid command was passed to manage_service()',
                 'error',
                 colors.ERROR)
    except dbus.exceptions.DBusException:
        print pm('Access denied while attempting to restart {0}'.format(service),
                 'error',
                 colors.ERROR)

"""
Check for root, exit if non-root
"""
def need_root():
    if os.geteuid() != 0:
    print pm('Root privileges are required to run this script, please re-run \
with root to continue', 'error', colors.ERROR)
    sys.exit(1)


def main():
    # argparse?

    # Steps based on guide from https://access.redhat.com/solutions/2944461
    # Stop skyring and salt-master on RHSC node (where script runs)
    manage_service('stop', 'skyring')
    manage_service('stop', 'salt-master')

    # On all storage nodes, stop salt-minion services and remove salt-keys
    somefunction()

    # Clean the mongodb on the RHSC node
    edit_db()
