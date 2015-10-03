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
#     hit or races are found, then read from it to find which events have
#     happened. Reading from this file removes the events from the memory
#     buffer associated with this file. If the breakpoints hit very often
#     and the reader does not keep up, the buffer may become full and the
#     new events will be discarded.
#
# That is it.
#
# Note that Python 3.4 or newer is needed here.
#
# Usage (run the script as root):
#   events.py [--max-hits=N] [-q]
#
# This script waits on /sys/kernel/debug/racehound/events file and outputs
# information about the events as soon as it is available in that file.
#
# Additionally, if '--max-hits=N' is specified, the breakpoints that hit N
# times or more will be removed.
#
# If -q (--quiet) is present, the script wiil only output a summary of the
# found races at the exit. It will not output the current events when it
# reads them.
#
# The script assumes debugfs is mounted to /sys/kernel/debug/.

import sys
import os.path
import selectors
import argparse
import re


BPS_FILE = '/sys/kernel/debug/racehound/breakpoints'
EVENTS_FILE = '/sys/kernel/debug/racehound/events'

ERR_NO_FILES = ''.join([
    'Please check that debugfs is mounted to /sys/kernel/debug ',
    'and kernel module \"racehound\" is loaded.'])

RE_RACE = re.compile(' '.join([
    r'Detected a data race on the memory block at (0x)?[0-9a-f]+',
    r'between the instruction at ([^ \t]+) \(comm: \"(.+)\"\)',
    r'and the instruction right before (.*) \(comm: \"(.+)\"\)']))

RE_RREAD = re.compile(' '.join([
    r'Detected a data race on the memory block at (0x)?[0-9a-f]+',
    r'that is about to be accessed by the instruction at ([^ \t]+)',
    r'\(comm: \"(.+)\"\):',
    r'the memory block was modified during the delay']))


def positive_int(string):
    value = int(string)
    if value <= 0:
        msg = "%r is not a positive integer" % string
        raise argparse.ArgumentTypeError(msg)
    return value


class RaceGroup(object):
    '''A group of races between a given pair of instructions

    'insn' - address of the instruction that under watch,
    'insn_comm' - 'comm' of the process that executed 'insn',
    'conflict_insn' - the address right after the instruction that performed
        a conflicting memory access (None if unknown),
    'conflict_comm' - 'comm' of the process that executed 'conflict_insn'
        (None if unknown).
    '''
    def __init__(self, insn, insn_comm, conflict_insn=None,
                 conflict_comm=None):
        self.insn = insn
        self.insn_comms = [insn_comm]
        self.conflict_insn = conflict_insn
        if conflict_comm:
            self.conflict_comms = [conflict_comm]
        else:
            self.conflict_comms = []

        # How many times this race was reported.
        self.count = 1

    def print_races(self):
        if self.conflict_insn:
            print('Race between %s and the insn right before %s.' %
                  (self.insn, self.conflict_insn))
            comms = list(set(self.insn_comms))
            print('The first insn was executed by:', ', '.join(comms))
            comms = list(set(self.conflict_comms))
            print('The second insn was executed by:', ', '.join(comms))
        else:
            print('Race between %s and some other code.' % self.insn)
            comms = list(set(self.insn_comms))
            print('The insn was executed by:', ', '.join(comms))

        print('The race was reported %d time(s).' % self.count)


def store_race_info(races, str_race):
    matched = re.search(RE_RACE, str_race)
    if matched:
        _, insn, insn_comm, conflict_insn, conflict_comm = matched.groups()
        key = insn + '#' + conflict_insn
    else:
        matched = re.search(RE_RREAD, str_race)
        if not matched:
            sys.stderr.write(
                'Unknown format of a race report: "%s".\n' % str_race)
            return

        _, insn, insn_comm = matched.groups()
        conflict_insn = None
        conflict_comm = None
        key = insn

    if key in races:
        races[key].count = races[key].count + 1
        races[key].insn_comms.append(insn_comm)
        if conflict_comm:
            races[key].conflict_comms.append(conflict_comm)
    else:
        races[key] = RaceGroup(
            insn, insn_comm, conflict_insn, conflict_comm)


def print_summary(races):
    if not races:
        print('No races found.')
    else:
        for _, grp in races.items():
            grp.print_races()
            print('')


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
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='do not output the events, just print a summary at exit')
    args = parser.parse_args()

    # Mapping: {racing_insns => race_info}
    races = {}

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
                        if line.startswith('[race]'):
                            line = line.rstrip()
                            store_race_info(races, line)
                            if not args.quiet:
                                print(line)
                            continue

                        bp = line.rstrip()
                        if not args.quiet:
                            print('BP hit:', bp)

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
                            if not args.quiet:
                                print(
                                    'BP %s was hit %d time(s), removing it' %
                                    (bp, args.max_hits))
                            remove_bp(bp)
        except KeyboardInterrupt:
            print_summary(races)
            sys.exit(1)
