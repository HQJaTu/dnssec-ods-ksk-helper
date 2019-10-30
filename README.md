# OpenDNSSEC KSK helper
Helper utility to display a human-readable state of a given ODS-enforced zone.

Also, understands KSK rollover and suggests what administrator needs to do next.

## Usage:
```bash
# dnssec-ods-ksk-helper.py
usage: dnssec-ods-ksk-helper.py [-h] ZONE-NAME
```

## Example run:
```bash
# dnssec-ods-ksk-helper.py example.com
OpenDNSSEC zone example.com information:
  Zone has no active keys
  Zone is waiting for a RSASHA256 (2048 bits) key with tag 60259 to be published
    Suggest: To publish the key, run following:
      1) ods-enforcer key ds-submit --zone example.com --keytag 60259
      2) ods-enforcer key export --zone example.com --keytype ksk --keystate publish --ds
      3) In your Domain name registrar's user interface:
         upload information from step 2) into zone example.com DNSSEC setup with following details:
         - Key tag: 60259
         - Key algorithm: 8 (RSASHA256)
         - Key digest type: 2 (SHA-256)
         - Key digest: (see key export output)
      4) ods-enforcer key ds-publish --zone example.com --keytag 60259
  Zone has DS-record with tag 60259
```
