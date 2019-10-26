#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import argparse
from lib.dnsutils import *
from lib.odsutils import *


def main():
    parser = argparse.ArgumentParser(description='OpenDNSSEC BIND zone configurator')
    parser.add_argument('--bind-dir', metavar='BIND-DIRECTORY', default='/etc/bind',
                        help='Destination directory to write to')
    parser.add_argument('zone', metavar='ZONES-NAME',
                        help='Your OpenDNSSEC hosted zone')
    args = parser.parse_args()

    ods = ODS(ZoneName=args.zone)
    print("OpenDNSSEC zone %s information:" % args.zone)
    active_key = ods.get_active_key()
    if active_key:
        print("  Zone has active %s (%d bits) key with tag %s" % (active_key.GetKeyName(),
                                                                  active_key.bits, active_key.tag))


if __name__ == '__main__':
    main()
