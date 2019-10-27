import dns.resolver
import random
import tldextract
import re


class DNS:
    DEFAULT_DNS_TIMEOUT = 5.0

    def __init__(self):
        self.resolver = dns.resolver.Resolver()

    def get_ds(self, zone: str):
        # Note:
        # Some top-level-domains have dots in them. Example: co.uk
        # First figure out what CAN be stripped. Then go for parent.
        initial_tld_info = tldextract.extract(zone)
        stripped_zone = re.sub(r'\.%s$' % initial_tld_info.suffix, '', zone)
        if '.' in stripped_zone:
            # Remove the subdomain and go for the parent domain
            zone_to_query = '.'.join(zone.split('.')[1:])
        else:
            # Nothing left to strip. Use the TLD
            zone_to_query = initial_tld_info.suffix

        ns = self._get_ns(zone_to_query)

        answer = self._query(zone, 'DS', ns)
        if not answer:
            return (ns, None)

        answer_parts = str(answer[0]).split()

        return (ns, {
            "keytag": answer_parts[0],
            "keyalgo": int(answer_parts[1]),
            "keylabels": int(answer_parts[2]),
            "key": answer_parts[3]
        })

    def _get_ns(self, zone: str):
        verbose = False
        initial_query_rr = dns.message.make_query(zone, dns.rdatatype.NS)
        depth = len(initial_query_rr.question[0].name)
        nameserver_to_use = random.choice(self.resolver.nameservers)
        query_rr = initial_query_rr

        last = False
        while not last:
            query = query_rr.question[0].name
            s = query.split(depth)

            last = s[0].to_unicode() == u'@'
            sub = s[1]

            if verbose:
                print('_get_ns() Looking up %s on %s' % (sub, nameserver_to_use))
            query_rr = dns.message.make_query(sub, dns.rdatatype.NS)
            response = dns.query.udp(query_rr, nameserver_to_use)

            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                if rcode == dns.rcode.NXDOMAIN:
                    raise Exception('%s does not exist.' % sub)
                else:
                    raise Exception('Error %s' % dns.rcode.to_text(rcode))

            rrset = None
            if len(response.authority) > 0:
                rrset = response.authority[0]
            else:
                rrset = response.answer[0]

            for rr in rrset:
                if rr.rdtype == dns.rdatatype.SOA:
                    if verbose:
                        print('_get_ns() Same server is authoritative for %s' % sub)
                else:
                    authority = rr.target
                    if verbose:
                        print('_get_ns() %s is authoritative for %s' % (authority, sub))

            # Pick a random nameserver and continue with that one
            # In DNS the answers are already randomized. We do the 2nd random regardless.
            nameserver_to_use = random.choice(self.resolver.query(authority).rrset).to_text()
            depth += 1

        return nameserver_to_use

    def _query(self, name: str, rr_type: str, resolver: str = None):
        verbose = False
        # Just pick one nameserver randomly from a set.
        # If only one exists, we'll use that one.
        if resolver:
            nameserver_to_use = resolver
        else:
            nameserver_to_use = random.choice(self.resolver.nameservers)

        try:
            answer = self.resolver.query(name, rr_type)
        except dns.resolver.NXDOMAIN:
            if verbose:
                print("Couldn't resolve %s-record for %s using %s. No such thing found!" % (rr_type, name, nameserver_to_use))
            return False
        except dns.exception.Timeout:
            if verbose:
                print("Couldn't resolve %s-record for %s using %s. Timed out!" % (rr_type, name, nameserver_to_use))
            return None
        except dns.resolver.NoAnswer:
            if verbose:
                print("Couldn't resolve %s-record for %s using %s. No answer!" % (rr_type, name, nameserver_to_use))
            return None

        return answer