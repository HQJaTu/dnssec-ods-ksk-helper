#!/usr/bin/env python3

# vim: autoindent tabstop=4 shiftwidth=4 expandtab softtabstop=4 filetype=python

import argparse
from lib.dnsutils import *
from lib.odsutils import *


def zone_status(zone: ODS):
    dns = DNS()
    print("OpenDNSSEC zone %s information:" % zone.zone)

    # ODS-enforcer status
    active_key = zone.get_active_key()
    if active_key:
        print("  Zone has active %s (%d bits) key with tag %s" % (active_key.get_key_name(),
                                                                  active_key.bits, active_key.tag))
    else:
        print("  Zone has no active keys")
        publish_key = zone.get_key_to_publish()
        if publish_key:
            print("  Zone is waiting for a %s (%d bits) key with tag %s to be published" % (publish_key.get_key_name(),
                                                                                            publish_key.bits,
                                                                                            publish_key.tag))
            print("    Suggest: To publish the key, run following:")
            print("      1) ods-enforcer key ds-submit --zone %s --keytag %s" % (zone.zone, publish_key.tag))
            print("      2) ods-enforcer key export --zone %s --keytype ksk --keystate publish --ds" % (zone.zone))
            print("      3) In your Domain name registrar's user interface:")
            print("         upload information from step 2) into zone %s DNSSEC setup with following details:" % (zone.zone))
            print("         - Key tag: %s" % publish_key.tag)
            print("         - Key algorithm: %d (%s)" % (publish_key.algorithm, publish_key.get_key_name()))
            print("         - Key digest type: %s (%s)" % (publish_key.ds_digest, publish_key.get_key_digest_name()))
            print("      4) ods-enforcer key ds-publish --zone %s --keytag %s" % (zone.zone, publish_key.tag))

    # DNS-status:
    (resolver, dns_result) = dns.get_ds(zone.zone)
    if dns_result:
        print("  Zone has DS-record with tag %s" % (dns_result["keytag"]))
        if active_key and active_key.tag == dns_result["keytag"]:
            print("  Tags in active key and DS-record match. All good.")
    else:
        print("  Zone has no DS-records in DNS %s" % resolver)


def main():
    parser = argparse.ArgumentParser(description='OpenDNSSEC BIND zone configurator')
    parser.add_argument('--bind-dir', metavar='BIND-DIRECTORY', default='/etc/bind',
                        help='Destination directory to write to')
    parser.add_argument('zone', metavar='ZONES-NAME',
                        help='Your OpenDNSSEC hosted zone')
    args = parser.parse_args()

    ods = ODS(ZoneName=args.zone)
    zone_status(ods)


if __name__ == '__main__':
    main()
