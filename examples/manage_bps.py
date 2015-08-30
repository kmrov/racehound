#!/usr/bin/env python3

# This example demonstrates how to control the set of the locations in the
# binary code of the kernel monitored by RaceHound.
#
# This can be used, for example, to create a system that dynamically adds
# and removes the breakpoints according to some policy to sweep through
# the given area of the kernel and find data races there. Might be similar
# to what DataCollider does for MS Windows. This example does not do this
# yet, however.
#
# The point is, one no longer needs to hack the kernel-mode components to do
# such sweeping with RaceHound. The policies can now be implemented in the
# user space using the interface provided by the kernel-mode part of
# RaceHound via the following files in debugfs:
#
#   * racehound/breakpoints - write data here to add or remove the
#     breakpoints on the code locations to be monitored. Reading from this
#     file lists the currently set breakpoints.
#
#   * racehound/events - poll this file to be notified when the breakpoints
#     hit, then read from it to find which ones have been hit. Reading from
#     this file removes the events from the memory buffer associated with
#     this file. If the breakpoints hit very often and the reader does not
#     keep up, the buffer may become full and the new events will be
#     discarded.
#
# That is it.
#
# Note that Python 3.4 or newer is needed here.
#
# Usage (run the script as root):
#   manage_bp_hits.py [--max-hits=N]
#
# This script waits on /sys/kernel/debug/racehound/events file and outputs
# information about the hit breakpoints placed by RaceHound as soon as it is
# available in that file.
#
# Additionally, if '--max-hits=N' is specified, the breakpoints that hit N
# times or more will be removed.
#
# The script assumes debugfs is mounted to /sys/kernel/debug/.

import sys
import os.path
import selectors
import argparse


BPS_FILE = '/sys/kernel/debug/racehound/breakpoints'
EVENTS_FILE = '/sys/kernel/debug/racehound/events'

ERR_NO_FILES = ''.join([
    'Please check that debugfs is mounted to /sys/kernel/debug ',
    'and kernel module \"racehound\" is loaded.'])


def positive_int(string):
    value = int(string)
    if value <= 0:
        msg = "%r is not a positive integer" % string
        raise argparse.ArgumentTypeError(msg)
    return value


def remove_bp(bp):
    '''Tell RaceHound to remove the given BP.
    See the Readme for RaceHound for the format and detais.'''
    with open(BPS_FILE, 'w') as f:
        f.write('-%s\n' % bp)


if __name__ == '__main__':
    desc = 'Demo for the API to control RaceHound from user space.'
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument(
        '--max-hits', metavar='N', nargs='?', type=positive_int, default=0,
        help='disable the breakpoint if it hits N times or more')
    args = parser.parse_args()

    for fl in [BPS_FILE, EVENTS_FILE]:
        if not os.path.exists(fl):
            sys.stderr.write('File not found: %s.\n' % fl)
            sys.stderr.write(ERR_NO_FILES)
            sys.stderr.write('\n')
            sys.exit(1)

    sel = selectors.DefaultSelector()
    with open(EVENTS_FILE, 'r') as f:
        sel.register(f, selectors.EVENT_READ)
        bp_hits = {} # The mapping {BP_string, number_of_hits}

        # Poll the "events" file and read the lines from it as they become
        # available.
        # If the user presses Ctrl-C, just exit.
        try:
            while True:
                events = sel.select()
                for key, mask in events:
                    for line in f:
                        bp = line.rstrip()
                        print("BP hit:", bp)

                        # Count the number of hits.
                        # If --max-hits=N is specified and the BP was hit
                        # N times, remove it. Note that the BP may be hit
                        # a few more times after this before it is actually
                        # removed.
                        if not bp in bp_hits:
                            bp_hits[bp] = 1
                        else:
                            bp_hits[bp] = bp_hits[bp] + 1

                        if bp_hits[bp] == args.max_hits:
                            print(
                                'BP %s was hit %d time(s), removing it' %
                                (bp, args.max_hits))
                            remove_bp(bp)
        except KeyboardInterrupt:
            sys.exit(1)
