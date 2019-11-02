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

    # DNS-status:
    (resolver, dns_result) = dns.get_ds(zone.zone)

    # Interpret the results
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
            if dns_result:
                print("    Suggest: To publish the key, run following:")
                print("      ods-enforcer key ds-seen --zone %s --keytag %s" % (zone.zone, publish_key.tag))
            else:
                print("    Suggest: To publish the key, do following:")
                print("      1) ods-enforcer key ds-submit --zone %s --keytag %s" % (zone.zone, publish_key.tag))
                print("      2) ods-enforcer key export --zone %s --keytype ksk --keystate publish --ds" % (zone.zone))
                print("      3) In your Domain name registrar's user interface:")
                print("         upload information from step 2) into zone %s DNSSEC setup with following details:" % (
                    zone.zone))
                print("         - Key tag: %s" % publish_key.tag)
                print("         - Key algorithm: %d (%s)" % (publish_key.algorithm, publish_key.get_key_name()))
                print(
                    "         - Key digest type: %s (%s)" % (publish_key.ds_digest, publish_key.get_key_digest_name()))
                print("         - Key digest: (see key export output)")
                print("      4) ods-enforcer key ds-publish --zone %s --keytag %s" % (zone.zone, publish_key.tag))
                print("      5) Wait. Eventually the key will be propagated according to chosen key policy.")

        ready_key = zone.get_ready_key()
        if ready_key:
            retired_keys = zone.get_retired_keys()
            if not retired_keys:
                print("  Zone is waiting for a %s (%d bits) key with tag %s to be DS-seen" % (ready_key.get_key_name(),
                                                                                              ready_key.bits,
                                                                                              ready_key.tag))
                print("    Suggest: To confirm key setup, run following:")
                print("      ods-enforcer key ds-seen --zone %s --keytag %s" % (zone.zone, ready_key.tag))
            elif dns_result:
                print("  Zone is waiting for KSK rollover")
                print("    Suggest: To perform KSK rollover, do following:")
                print("      To get new key published:")
                print("      1) ods-enforcer key export --zone %s --keytype ksk --keystate ready --ds" % (zone.zone))
                print("      2) In your Domain name registrar's user interface:")
                print("         upload information from step 1) into zone %s DNSSEC setup with following details:" % (
                    zone.zone))
                print("         - Key tag: %s" % ready_key.tag)
                print("         - Key algorithm: %d (%s)" % (ready_key.algorithm, ready_key.get_key_name()))
                print(
                    "         - Key digest type: %s (%s)" % (ready_key.ds_digest, ready_key.get_key_digest_name()))
                print("         - Key digest: (see key export output)")
                print("      3) ods-enforcer key ds-seen --zone %s --keytag %s" % (zone.zone, ready_key.tag))

                if dns_result["keytag"] in retired_keys:
                    retired_key = retired_keys[dns_result["keytag"]]
                    print("")
                    print("      To get old key retired:")
                    print("      1) Important: Do this only after new key steps have been completed!")
                    print("      2) ods-enforcer key ds-gone --zone %s --keytag %s" % (zone.zone, retired_key.tag))
            else:
                print("  Zone is royally messed up!")

    if dns_result:
        print("  Zone has DS-record with tag %s" % (dns_result["keytag"]))
        if active_key and active_key.tag == dns_result["keytag"]:
            print("  Found tags in active key and DS-record. Tags match. All good. Nothing to do.")
    else:
        print("  Zone has no DS-records in DNS %s" % resolver)

    print("\nHint: Verify the status by visiting https://dnssec-analyzer.verisignlabs.com/%s" % zone.zone)


def main():
    parser = argparse.ArgumentParser(description='OpenDNSSEC KSK helper utility')
    parser.add_argument('zone', metavar='ZONE-NAME',
                        help='Your OpenDNSSEC hosted zone')
    args = parser.parse_args()

    ods = ODS(ZoneName=args.zone)
    zone_status(ods)


if __name__ == '__main__':
    main()
