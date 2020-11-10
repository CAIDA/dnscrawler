from collections import defaultdict
from functools import lru_cache
from random import choice
from tldextract import extract
if __name__ == "__main__":
    import constants
    from logger import log
    from pydns import PyDNS
    from querysummary import QuerySummary
    from querysummarylist import QuerySummaryList
else:
    from . import constants
    from .logger import log
    from .pydns import PyDNS
    from .querysummary import QuerySummary
    from .querysummarylist import QuerySummaryList

class DNSResolver:
    def __init__(self, socket_factories=[]):
        self.pydns = PyDNS(socket_factories)
        self.active_resolutions = set()
        self.past_resolutions = {}
        self.root_servers = {
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
        };
        self.nameservers = defaultdict(set, self.root_servers)
    # Return a random rootserver for querying
    def get_root_server(self):
        server = choice(list(self.root_servers))
        return {server:self.root_servers[server]}

    # Return the ips and ns records that are authoritative for a hostname
    # current_name -  The hostname to select NS records for, from a given DNS query
    # records - The results of a pydns query
    # output_dict - Dictionary to store all ns, tld, sld, ip, and hazardous_domain data,
    #               If not provided, parse will not attempt to recurse down for any missing ips
    # prefix - String indicating category of resolved hostnames, particulary if 
    #          the hostname came from resolving a public suffix dependency (ex. resolving co.uk)
    # isNS - A flag to indicate that function call came from resolving a prior NS record
    def parse(self, current_name, records, output_dict=None, prefix="", isNS=False):
        # Convert current_name to lower case for sake of uniformity
        current_name = current_name.lower()
        # Create dictionary to store all ips for each authoritative ns
        auth_ns = {}
        # Pull all nameservers for current_name into a set
        ns_set = set()
        # Pull all ip-ns pairs into a dict for comparison with ns_set
        ip_dict = self.nameservers
        for record in records:
            # Add all nameservers for names that are a substring of current_name to ns_set
            if record['type'] == 'NS' and record['name'].lower() in current_name:
                # Convert data to lower case for sake of uniformity
                ns_set.add(record['data'].lower())
                # If output_dict is provided (not parsing tld data) then store the ns data in output_dict
                if output_dict is not None:
                    # Convert data to lower case for sake of uniformity
                    output_dict[prefix+'ns'].add(record['data'].lower())
            elif record['type'] in ('A','AAAA'):
                # Add all ips for a hostname to a set (ex. 'ns1.example.com':{1.1.1.0, 1.1.1.1})
                # Convert data to lower case for sake of uniformity
                ip_dict[record['name'].lower()].add(record['data'].lower())
                # If output_dict is provided (not parsing tld data) then store the ip data in output_dict
                if output_dict is not None:
                    # If A record then store in ipv4, else store in ipv6
                    if record['type'] == 'A':
                        # Convert data to lower case for sake of uniformity
                        output_dict[prefix+'ipv4'].add(record['data'].lower())
                    else:
                        # Convert data to lower case for sake of uniformity
                        output_dict[prefix+'ipv6'].add(record['data'].lower())
                    # If an A/AAAA record exists for the current name, add it straight to output_dict
                    # so that it can be parsed for tlds and slds
                    if record['name'].lower() == current_name:
                        output_dict[record['name'].lower()].add(record['data'].lower())
                        # If isNS is true, query came from resolving a previous NS record, so the corresponding
                        # a record can be treated as a nameserver
                        if isNS:
                            ns_set.add(current_name)
        # Compile sets of all ips for authoritative ns into auth_ns
        for ns_name in ns_set:
            # Seperate ns_name and current_name by domain and suffix in order to avoid
            # reresolution if both the ns and the current_name belong to the same domain
            # (ie. don't reresolve ns1.example.com if current name is example.com)
            extracted_ns = extract(ns_name)
            extracted_current = extract(current_name)
            # Get sanitized name (domain + suffix) for checking if in active_resolutions
            ns_name_parts = [part for part in extracted_ns.domain.split('.')+extracted_ns.suffix.split('.') if len(part) > 0]
            current_name_parts = [part for part in extracted_current.domain.split('.')+extracted_current.suffix.split('.') if len(part) > 0]
            sanitized_ns_name = f"{'.'.join(ns_name_parts)}."
            sanitized_current_name = f"{'.'.join(current_name_parts)}."
            # Add TLD and SLD data to output_dict
            if output_dict is not None:
                # Add data for each ns
                if len(extracted_ns.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_ns.domain}.{extracted_ns.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_ns.suffix}.")
                elif len(ns_name_parts) > 1:
                    output_dict[prefix+'sld'].add(sanitized_ns_name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(ns_name_parts[1:])}.")
                else:
                    output_dict[prefix+'tld'].add(f"{ns_name_parts[0]}.")

                # Add data for current_name
                if len(extracted_current.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_current.domain}.{extracted_current.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_current.suffix}.")
                elif len(current_name_parts) > 1:
                    output_dict[prefix+'sld'].add(sanitized_current_name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(current_name_parts[1:])}.")
                else:
                    output_dict[prefix+'tld'].add(f"{current_name_parts[0]}.")
            # If ip for the hostname is provided in the additional section then use that
            if ns_name in ip_dict:
                auth_ns[ns_name] = ip_dict[ns_name].copy()
            elif output_dict is not None and sanitized_ns_name in self.active_resolutions:
                # Else if the current ns_name is currently being resolved, add current_name to non hazardous list
                output_dict['nonhazardous_domains'].add(current_name)
            elif output_dict is not None and (
                    extracted_ns.domain != extracted_current.domain or 
                    extracted_ns.suffix != extracted_current.suffix
                ):            
                # Add name to active_resolutions, this will prevent it from
                # being reresolved in a cyclic dependency, but only add if not tld
                self.active_resolutions.add(sanitized_ns_name)
                # Else if the current ns_name is not already being resolved and
                # the ns_name and the current_name are not part of the same domain and no 
                # output_dict is provided (ie. not parsing a tld) try resolving the hostname for its ips
                reresolved_ns = self.map_name(original_name=ns_name, output_dict=output_dict, 
                    prefix=prefix, isNS=True).get(ns_name, None)
                if reresolved_ns is not None:
                    # If reresolution is successful then add to auth_ns
                    auth_ns[ns_name] = reresolved_ns.copy()
        return auth_ns

    # Recursively resolve a given hostname
    # original_name - The hostname
    # output_dict - Dictionary to store all ns, tld, sld, ip, and hazardous_domain data
    # prefix - String indicating category of resolved hostnames, particulary if 
    #          the hostname came from resolving a public suffix dependency (ex. resolving co.uk)
    # name - A truncated form of the name used as the default for handling queries
    # isNS - A flag to indicate that function call came from resolving a prior NS record
    def map_name(self, original_name, output_dict, prefix="", name=None, isNS=False):
        # Initialize auth_ns to store the authoritative nameservers to query in each iteration
        auth_ns = None
        # When output_dict is empty from first creation, 
        # create a set within output_dict to store hazardous domains, misconfigurations, ipv4, 
        # ipv6, ns data, and to store nonhazardous domains in cases of cyclic dependencies
        if isinstance(output_dict,dict) and len(output_dict) == 0:
            output_dict['misconfigured_domains'] = defaultdict(QuerySummaryList)
            output_dict['hazardous_domains'] = QuerySummaryList()
            output_dict['nonhazardous_domains'] = set()
            output_dict['ipv4'] = set()
            output_dict['ipv6'] = set()
            output_dict['ns'] = set()
            output_dict['tld'] = set()
            output_dict['sld'] = set()
            output_dict['ps_ns'] = set()
            output_dict['ps_ipv4'] = set()
            output_dict['ps_ipv6'] = set()
            output_dict['ps_tld'] = set()
            output_dict['ps_sld'] = set()


        # Extract and generate name_parts from name if available
        # Else extract from original_name
        if not name:
            # Convert original name to lowercase and add trailing period for uniformity
            # Save original for querying where minimized name doesnt work
            original_name =  original_name.lower()
            if original_name[-1] != ".":
                original_name = f"{original_name}."
            name = original_name     
        # Split domain and suffix by periods and remove any empty strings
        name_parts = [part for part in name.split('.') if len(part) > 0]
        extracted_name = extract(name)
        # Return cached past resolutions to prevent cyclic dependencies and reduce queries
        if name in self.past_resolutions:
            return self.past_resolutions[name]
        # If name is only tld
        isTLD = len(name_parts) == 1
        # If extracted_name doesn't have a domain then name must be a suffix
        isSuffix = extracted_name.domain == ''
        if isTLD:
            # Base case: If name is tld, then select a rootserver to use as the authoritative ns
            auth_ns = self.get_root_server()
        else:
            # Create name from every part of current name except first (ex. ns1.example.com -> example.com)
            superdomain = f"{'.'.join(name_parts[1:])}."
            # These are the authoritative nameservers from the super domain
            # (ie. com => a.gtld-servers.net => google.com)
            if isSuffix:
                prefix = "ps_"
            auth_ns = self.map_name(name=superdomain, output_dict=output_dict, prefix=prefix, original_name=original_name);

        # Authoritative nameserver querying split into two parts: First query the authoritative nameservers 
        # for the superdomain to get the the authoritative nameservers for the domain, then querying process
        # repeats with the authoritative nameservers for the domain to get the final set of authoritative nameservers
        for i in range(2):
            new_auth_ns = {}
            query_response_list = []
            # Query name for each ip for each ns in auth_ns
            for ip_set in auth_ns.values():
                for ip in ip_set:
                    query_name = name
                    query_response = self.pydns.query(domain=query_name, nameserver=ip)
                    query_response_list.append(query_response)
                    records = query_response['data'].values()
                    if len(records) == 0:
                        # Create flag to check if RCODE is 3 (NXDOMAIN); if it is, do not repeat query with original name
                        nxdomain = "timeout" not in query_response['rcodes'] and query_response['rcodes'][2] == 3
                        if not nxdomain and name != original_name:
                            query_name = original_name
                            query_response = self.pydns.query(domain=query_name, nameserver=ip)
                        records = query_response['data'].values()
                        nxdomain = "timeout" not in query_response['rcodes'] and query_response['rcodes'][2] == 3
                        # As long as query response still is not (NXDOMAIN), reuse previous zone cut's 
                        # nameservers for next set of queries
                        if len(records) == 0 and not nxdomain:
                            new_auth_ns.update(auth_ns)
                            continue
                    # If isTLD do not provide output_dict for parse as tlds do not need to be recursed
                    new_auth_ns.update(self.parse(query_name, records, output_dict if not isTLD else None, prefix, isNS=isNS))
            # If auth_ns is still empty => query returned no nameservers so domain is hazardous,
            # unless a cyclic dependency has occurred, in which case nameserver will be added to nonhazardous domains
            if len(new_auth_ns) == 0 and name not in output_dict['nonhazardous_domains']:
                # If error on first itereation and name is not ip add name to output_dicts hazardous set
                # Else add name to misconfiguration set for missing ns records
                if i==0:
                    if name_parts[-1].isdigit():
                        for query_response in query_response_list:
                            output_dict['misconfigured_domains']['ip_ns_records'].add(
                                QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver'])
                            )
                    else:
                        for query_response in query_response_list:
                            output_dict['hazardous_domains'].add(QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver']))
                else:
                    for query_response in query_response_list:
                        output_dict['misconfigured_domains']['missing_ns_records'].add(
                            QuerySummary(name=name,rcodes=query_response['rcodes'], nameserver=query_response['nameserver'])
                        )
                if len(extracted_name.domain) > 0:
                    output_dict[prefix+'sld'].add(f"{extracted_name.domain}.{extracted_name.suffix}.")
                    output_dict[prefix+'tld'].add(f"{extracted_name.suffix}.")
                elif len(name_parts) > 1:
                    output_dict[prefix+'sld'].add(name)
                    output_dict[prefix+'tld'].add(f"{'.'.join(name_parts[1:])}.")
                else:
                    output_dict[prefix+'tld'].add(f"{name_parts[0]}.")
                # Break iteration since is new_auth_ns is empty, no further resolutions can be made
                break
            auth_ns = new_auth_ns
        # Remove name from active_resolutions to end the hold on it being reresolved
        self.active_resolutions.discard(name)
        # Add to past_resolutions so that reresolutions hit the cache rather than triggering another cyclic dependency
        self.past_resolutions[name] = new_auth_ns
        return new_auth_ns

    # Return a dictionary containing all the ns, tld, sld, ip, and hazardous domains for a given hostname,
    # filters the output from map_name
    # name - The hostname to search for
    def get_domain_dict(self, name): 
        self.nameservers = defaultdict(set, self.root_servers)
        # Initialize the dictionary to store the raw zone data
        output_dict = defaultdict(set)
        self.map_name(name, output_dict)
        # Initialize the dictionary to store the formatted zone data
        domain_dict = {"query":name}
        # Convert values in hazard, ns, ip, and tld/sld sets to uppercase to remove any case duplicates
        # Add ip, ns and hazardous domain data to domain_dict, casting to list to make the data JSON serializable.
        domain_dict['misconfigured_domains'] = {}
        for k,v in output_dict['misconfigured_domains'].items():
            domain_dict['misconfigured_domains'][k] = v.queries
        domain_dict['hazardous_domains'] = output_dict['hazardous_domains'].queries
        domain_dict['ns'] = list({val.lower() for val in output_dict['ns']})
        domain_dict['ipv4'] = list({val.lower() for val in output_dict['ipv4']})
        domain_dict['ipv6'] = list({val.lower() for val in output_dict['ipv6']})
        domain_dict['tld'] = list({val.lower() for val in output_dict['tld']})
        domain_dict['sld'] = list({val.lower() for val in output_dict['sld']})
        domain_dict['ps_ns'] = list({val.lower() for val in output_dict['ps_ns']})
        domain_dict['ps_ipv4'] = list({val.lower() for val in output_dict['ps_ipv4']})
        domain_dict['ps_ipv6'] = list({val.lower() for val in output_dict['ps_ipv6']})
        domain_dict['ps_tld'] = list({val.lower() for val in output_dict['ps_tld']})
        domain_dict['ps_sld'] = list({val.lower() for val in output_dict['ps_sld']})
        return domain_dict

# if __name__ == "__main__":
#     resolver = DNSResolver()
#     zone_data = resolver.get_domain_dict("google.com")
        

