from datetime import datetime


class OdsKey:
    # Key statuses in ODS enforcer
    ODS_ZONE_STATUS_ACTIVE = 'active'
    ODS_ZONE_STATUS_RETIRE = 'retire'
    ODS_ZONE_STATUS_PUBLISH = 'publish'
    ODS_ZONE_STATUS = [ODS_ZONE_STATUS_ACTIVE, ODS_ZONE_STATUS_RETIRE, ODS_ZONE_STATUS_PUBLISH]

    # Algorithm numbers:
    # https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
    DNSSEC_KEY_ALGORITHMS = {
        0: "DELETE",  # Delete DS
        1: "RSAMD5",  # RSA/MD5 (deprecated)
        2: "DH",  # Diffie-Hellman
        3: "DSA",  # DSA/SHA1
        4: None,
        5: "RSASHA1",  # RSA/SHA-1
        6: "DSA-NSEC3-SHA1",  # DSA-NSEC3-SHA1
        7: "RSASHA1-NSEC3-SHA1",  # RSASHA1-NSEC3-SHA1
        8: "RSASHA256",  # RSA/SHA-256
        9: None,
        10: "RSASHA512",  # RSA/SHA-512
        11: None,
        12: "ECC-GOST",  # GOST R 34.10-2001
        13: "ECDSAP256SHA256",  # ECDSA Curve P-256 with SHA-256
        14: "ECDSAP384SHA384",  # ECDSA Curve P-384 with SHA-384
        15: "ED25519",  # Ed25519
        16: "ED448",  # Ed448
        252: "INDIRECT",
        253: "PRIVATEDNS",
        254: "PRIVATEOID",
        255: None
    }

    DNSSEC_DS_DIGEST = {
        0: None,
        1: "SHA-1",
        2: "SHA-256",
        3: "GOST R 34.11-94",
        4: "SHA-384"
    }

    def __init__(self, Type: str, Tag: str, State: str, Bits: int, Algorithm: int, NextTransition: datetime,
                 DSDigest: int = None):
        if not (Type == 'KSK' or Type == 'ZSK'):
            raise ValueError("Key type needs to be either KSK or ZSK!")
        if State not in OdsKey.ODS_ZONE_STATUS:
            raise ValueError("Key type needs to be either KSK or ZSK!")
        if Algorithm not in OdsKey.DNSSEC_KEY_ALGORITHMS.keys():
            raise ValueError("Unknown key algorithm %d!" % Algorithm)
        if Type == 'KSK' and DSDigest:
            if DSDigest not in OdsKey.DNSSEC_DS_DIGEST.keys():
                raise ValueError("Unknown key algorithm %d!" % DSDigest)

        self.type = Type
        self.tag = Tag
        self.state = State
        self.algorithm = Algorithm
        self.bits = Bits
        self.next_transition = NextTransition

        if Type == 'KSK':
            self.ds_digest = DSDigest
        else:
            self.ds_digest = None

    def get_key_name(self):
        return OdsKey.DNSSEC_KEY_ALGORITHMS[self.algorithm]

    def get_key_digest_name(self):
        if not self.ds_digest:
            return None

        return OdsKey.DNSSEC_DS_DIGEST[self.ds_digest]
