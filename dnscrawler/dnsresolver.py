from dns import query as dnsquery, message as dnsmessage, rdatatype
from functools import lru_cache
from random import choice
from tldextract import extract
if __name__ == "__main__":
    import constants
    from logger import log
    import pydns
else:
    from . import constants
    from .logger import log
    from . import pydns

class DNSResolver:
    def __init__(self):
        self.nameservers = {
            "a.root-servers.net.":{"198.41.0.4"},
            "b.root-servers.net.":{"199.9.14.201"},
            "c.root-servers.net.":{"192.33.4.12"},
            "d.root-servers.net.":{"199.7.91.13"},
            "e.root-servers.net.":{"192.203.230.10"},
            "f.root-servers.net.":{"192.5.5.241"},
            "g.root-servers.net.":{"192.112.36.4"},
            "h.root-servers.net.":{"198.97.190.53"},
            "i.root-servers.net.":{"192.36.148.17"},
            "j.root-servers.net.":{"192.58.128.30"},
            "k.root-servers.net.":{"193.0.14.129"},
            "l.root-servers.net.":{"199.7.83.42"},
            "m.root-servers.net.":{"202.12.27.33"},
        }
    # Return the ips and ns records that are authoritative for a hostname
    # current_name -  The hostname to select NS records for, from a given DNS query
    # records - The results of a pydns query
    # output_dict - Dictionary to store all ns, tld, sld, ip, and hazardous_domain data,
    #               If not provided, parse will not attempt to recurse down for any missing ips
    def parse(self, current_name, records, output_dict=None):
        # Create dictionary to store all ips for each authoritative ns
        auth_ns = {}
        # Pull all nameservers for current_name into a set
        ns_set = set()
        # Pull all ip-ns pairs into a dict for comparison with ns_set
        ip_dict = self.nameservers
        for record in records:
            # Add all nameservers for current_name to ns_set
            if record['type'] == 'NS' and record['name'] == current_name:
                ns_set.add(record['data'])
            elif record['type'] in ('A','AAAA'):
                # Add all ips for a hostname to a set (ex. 'ns1.example.com':{1.1.1.0, 1.1.1.1})
                ip_dict.setdefault(record['name'], set()).add(record['data'])
        # Compile sets of all ips for authoritative ns into auth_ns
        for name in ns_set:
            if name in ip_dict:
                # If ip for the hostname is provided in the additional section then use that
                auth_ns[name] = ip_dict[name].copy()
            elif output_dict is not None:
                # Else try reresolving the hostname for its ips
                reresolved_ns = self.map_name(name,output_dict).get(name, None)
                if reresolved_ns is not None:
                    # If reresolution is successful then add to auth_ns
                    auth_ns[name] = reresolved_ns.copy()
        return auth_ns

    # Recursively resolve a given hostname
    # name - The hostname
    # output_dict - Dictionary to store all ns, tld, sld, ip, and hazardous_domain data
    # query_root - Flag to determine if to query root-servers
    def map_name(self, name, output_dict, query_root=False):
        # Initialize auth_ns to store the authoritative nameservers to query in each iteration
        auth_ns = None
        # When output_dict is empty from first creation, 
        # create a set within output_dict to store hazardous domains
        if len(output_dict) == 0:
            output_dict['hazardous'] = set()
        # Use tldextract to get just domain + suffix for each name
        extracted_name = extract(name)
        # Split domain and suffix by periods and remove any empty strings
        name_parts = [part for part in extracted_name.domain.split('.')+extracted_name.suffix.split('.') if len(part) > 0]
        # Set name to recombined name_parts and add trailing period
        name = ".".join(name_parts)+"."
        # If name is only tld
        isTLD = len(name_parts) == 1
        if isTLD:
            # Base case: Only tld and querying root-server
            if query_root:
                records = pydns.query_root(domain=name, record_types=("NS","A","AAAA")).values()
                # Do not provide output_dict for parse as tlds do not need to be recursed
                return self.parse(name, records)
            else:
                # Query the root-servers with same name to get auth_ns for tld
                auth_ns = self.map_name(name=name, output_dict=output_dict, query_root=True);
        else:
            # Create name from every part of current name except first (ex. ns1.example.com -> example.com)
            superdomain = '.'.join(name_parts[1:])+'.'
            auth_ns = self.map_name(name=superdomain, output_dict=output_dict);

        # Query name for each ip for each ns in auth_ns
        new_auth_ns = {}
        for ip_set in auth_ns.values():
            for ip in ip_set:
                records = pydns.query(domain=name, nameserver=ip, record_types=("NS","A","AAAA")).values()
                new_auth_ns.update(self.parse(name, records, output_dict))
        # If new_auth_ns is still empty => query returned no nameservers so domain is hazardous
        if len(new_auth_ns) == 0:
            # Add name to output_dicts hazardous set
            output_dict['hazardous'].add(name)
        # Only update output_dict with data if isTLD is false
        if not isTLD:
            output_dict.update(new_auth_ns)
        return new_auth_ns
        

if __name__ == "__main__":
    resolver = DNSResolver()
    output_dict = {}
    resolver.map_name("google.com", output_dict)
    print(output_dict)

