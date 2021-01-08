from collections import defaultdict
from datetime import datetime, timezone
import logging
from random import choice
import time

import asyncio
from tldextract import extract

import dnscrawler.constants as constants
from dnscrawler.logger import log
from dnscrawler.node import Node, format_hostname, format_ip
from dnscrawler.nodelist import NodeList
from dnscrawler.pydns import PyDNS
from dnscrawler.querysummary import QuerySummary
from dnscrawler.querysummarylist import QuerySummaryList

logger = logging.getLogger(__name__)


class DNSResolver:
    '''DNSResolver acts a recursive resolver for all hostname
    dependencies

    Args:
        socket_factories (optional): Defaults to empty list. List of
            dicts with keys 'addr' and 'port' for the ip address and
            port of a SOCKS5 proxy which queries can be routed through.
        ipv4_only (optional): Defaults to False. If True, resolver will
            only send queries to ipv4 nameservers to avoid ipv6
            timeouts.

    Attributes:
        pydns (PyDns): DNS query handler for the resolver.
        ipv4_only (bool): If True, resolver will only send queries to
            ipv4 nameservers to avoid ipv6 timeouts.
        active_resolutions (set): Set containing the hostnames currently
            being resolved.
        root_servers (dict): Maps each root server to a set containing
            its ip addresses.
        nameservers (defaultdict(set)): Contains the collection of
            nameservers and corresponding ips found throughout
            resolution, as a short-term cache during a single hostname
            resolution.
    '''

    def __init__(self, socket_factories: list = [], ipv4_only: bool = False):
        self.pydns = PyDNS(socket_factories, ipv4_only)
        self.ipv4_only = ipv4_only
        self.active_resolutions = set()
        self.past_resolutions = {}
        self.root_servers = constants.ROOT_SERVERS
        self.nameserver_ip = defaultdict(set, self.root_servers)

    async def __aenter__(self):
        '''Initialize PyDNS context manager'''
        await self.pydns.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        '''Close PyDNS context manager'''
        await self.pydns.__aexit__(exc_type, exc, tb)

    @staticmethod
    def get_timestamp() -> str:
        '''
        Get RFC3339 timestamp

        Valid RFC 3339 timestamps come in the form:

            YYYY-MM-DDTHH:mm:ss.SSZ (ISO 8601) or
            YYYY-MM-DD HH:mm:ss.SSZ

        Returns:
            Timestamp in ISO 8601 form
        '''
        timestamp = datetime.now(timezone.utc).astimezone()
        return timestamp.isoformat()

    def get_root_server(self) -> dict:
        ''' Get a random root-server for querying

        Returns:
            Dict mapping a root-server to a set containing its ip
            addresses
        '''
        server = choice(list(self.root_servers))
        return {server: self.root_servers[server]}

    def _extract_hostname_dependencies(
        self,
        name: str,
        dependencies: defaultdict(str),
        prefix: str = "",
        is_ns: bool = False
    ):
        '''Pulls (ps_)tld and (ps_)sld dependencies from a hostname

        Args:
            name: The hostname to pull dependencies from
            dependencies: Dict to store dependencies in
            prefix (optional): Defaults to "". Used primarily to
                differentiate between dependencies as a result of
                hostnames above and below the public suffix level.
            is_ns (optional): Defaults to False. Flag to determine
                whether to exclude the sld if it matches the hostname
        '''
        extracted_name = extract(name)
        name_parts = list(filter(None, name.split(".")))
        # Get registrable domain from hostname
        if extracted_name.domain:
            name_sld = f"{extracted_name.domain}.{extracted_name.suffix}."
            name_tld = f"{extracted_name.suffix}."
        elif len(name_parts) > 1:
            name_sld = name
            name_tld = f"{'.'.join(name_parts[1:])}."
        else:
            name_sld = None
            name_tld = f"{name_parts[0]}."
        # Don't add sld if sld matches name and name is a nameserver
        if name_sld and (not is_ns or name_sld != name):
            dependencies[f"{prefix}sld"].add(name_sld)
        dependencies[f"{prefix}tld"].add(name_tld)

    async def _parse_records(
        self,
        current_name: str,
        records: set,
        dependencies: dict = None,
        prefix: str = "",
        is_ns: bool = False,
        current_node: Node = None,
        node_list: NodeList = None,
        node_trust_type: str = "parent"
    ) -> dict:
        '''Get the nameservers and corresponding ips for a host from an
        RRset.

        Args:
            current_name: Hostname to search records for from a given
                RRset.
            records: A set of DNSRecords representing an RRset.
            dependencies (optional): Defaults to None. A dictionary to
                store a host's ns, tld, ip, etc. dependencies. If
                provided, will try to find the ip addresses for any
                nameservers in the RRset that are missing A/AAAA
                records.
            prefix (optional): Defaults to "". If a dependencies dict is
                also provided, will also label the stored ns, tld, ip,
                etc. found in the RRset with the prefix. Used primarily
                to differentiate between dependencies as a result of
                hostnames above and below the public suffix level.
            is_ns (optional): Defaults to False. If True, indicates that
                current_name is a nameserver found in a prior NS record.
                As a result, if the current RRset contains an A/AAAA
                record for current_name, but no NS record, those ip
                addresses will still be treated as if an NS record was
                provided.
            current_node (optional): Defaults to None. The Node
                referring to current_name. If both current_node and
                node_list are provided, will preserve the hierarchical
                dependencies found in the RRset.
            node_list (optional): Defaults to None. The NodeList will be
                used to create new nodes for the hostnames/ip addresses
                found in the RRset. If both current_node and node_list
                are provided, will preserve the hierarchical
                dependencies found in the RRset.
            node_trust_type (optional): Defaults to "parent". Labels the
                zonal relationship between current_name and the
                nameserver queried to generate the RRset (ex. parent,
                child, provisioning).

        Returns:
            Dict of the nameservers and corresponding ips for
            current_name found in records

        Raises:
            ValueError: If either (but not both) node_list and
                current_node are not None or if an invalid
                node_trust_type is provided.
        '''

        # Flag to check if general dependency data should be preserved (ie.
        # not parsing tld data)
        can_generate_dependencies = dependencies is not None
        # Flag to check if should preserve hierachical node data
        can_generate_nodes = node_list and current_node
        if not can_generate_nodes and (node_list or current_node):
            raise ValueError(
                "Both node_list and current_node must be set to"
                "generate hierachical node data:", node_list, current_node)
        elif node_trust_type not in constants.VALID_NODE_TRUST_TYPES:
            raise ValueError("Invalid node_trust_type:", node_trust_type)

        current_name = format_hostname(current_name)
        # Create dictionary to store all ips for each authoritative ns
        auth_ns = {}
        # Pull all nameservers for current_name ffrom current RRset into
        # a set
        current_name_ns = set()
        # Pull all prior ip-ns pairs, as well ip-ns pairs from current
        # RRset into dictionary and match with current_name_ns
        nameserver_ip = self.nameserver_ip
        # Map current_name's nameservers to its nameserver nodes
        node_nameservers = {}
        # Flag to check if node is part of the resolution of a public
        # suffix hostname
        is_public_suffix = prefix == "ps_"
        for record in records:
            # Add all nameservers for names that current_name ends with
            # to current_name_ns. (ex. If current_name is
            # ns1.example.com, and nameserver is for com or example.com)
            record_name = format_hostname(record.name)
            if record.rrtype == 'NS' and current_name.endswith(record_name):
                record_data = format_hostname(record.data)
                # If the record is for current_name capture the
                # current_name -> nameserver relationships in the
                # nodelist
                if record_name == current_name and can_generate_nodes:
                    node_type = Node.infer_node_type(record_data, is_ns=True)
                    record_node = node_list.create_node(record_data, node_type)
                    record_node.is_public_suffix = is_public_suffix
                    node_nameservers[record_data] = record_node
                    current_node.trusts(record_node, node_trust_type)
                current_name_ns.add(record_data)
                if can_generate_dependencies:
                    dependencies[f"{prefix}ns"].add(record_data)
            elif record.rrtype in ('A', 'AAAA'):
                record_data = format_ip(record.data)
                # Add all ips for a hostname to a set inside
                # nameserver_ip
                # Ex. {'ns1.example.com':{1.1.1.0, 1.1.1.1}}
                nameserver_ip[record_name].add(record_data)
                # If dependencies is provided (not parsing tld data)
                # then store the ip data in dependencies
                if can_generate_dependencies:
                    # If A record then store in ipv4, else store in ipv6
                    if record.rrtype == 'A':
                        dependency_label = f"{prefix}ipv4"
                    else:
                        dependency_label = f"{prefix}ipv6"
                    dependencies[dependency_label].add(record_data)
                # If the record is for current_name capture the
                # current_name -> ip relationships in the nodelist
                if record_name == current_name:
                    if can_generate_nodes:
                        node_type = Node.infer_node_type(record.data)
                        record_node = node_list.create_node(record.data, node_type)
                        record_node.is_public_suffix = is_public_suffix
                        current_node.trusts(record_node, node_trust_type)
                    # If is_ns is true, current_name came from resolving
                    # a previous NS record, so the hostname from the
                    # A/AAAA record can be treated as a nameserver
                    if is_ns:
                        current_name_ns.add(current_name)

        # Get registrable domain from current hostname
        extracted_current_name = extract(current_name)
        if can_generate_dependencies:
            # Add dependency data for current_name
            self._extract_hostname_dependencies(current_name, dependencies, is_ns=is_ns)
        # Compile sets of all ips for authoritative ns into auth_ns
        # Seperate ns_name and current_name by domain and suffix in
        # order to avoid reresolution if both the ns and the
        # current_name belong to the same domain (ie. don't reresolve
        # ns1.example.com if current name is example.com)
        for ns_name in current_name_ns:
            # If ns name is '.' skip further parsing for current
            # iteration and pass an empty set for ip addresses
            if ns_name == ".":
                auth_ns[ns_name] = set()
                continue
            extracted_ns_name = extract(ns_name)
            ns_name_sld = f"{extracted_ns_name.domain}.{extracted_ns_name.suffix}."
            # Add nameservers's TLD and SLD data to dependencies
            if can_generate_dependencies:
                self._extract_hostname_dependencies(ns_name, dependencies, prefix, is_ns=True)

            # If A/AAAA records for the current nameserver were found in
            # the RRset and added to nameserver_ip, then add those ips
            # to auth_ns
            # Else if the current ns_name is currently being resolved,
            # add to nonhazardous domains
            # Else if the current ns_name is not already being resolved
            # and the ns_name and the current_name are not part of the
            # same domain and try resolving the nameserver for its ips
            # current_name to non hazardous list
            if ns_name in nameserver_ip:
                auth_ns[ns_name] = nameserver_ip[ns_name].copy()
            elif can_generate_dependencies and ns_name_sld in self.active_resolutions:
                dependencies['nonhazardous_domains'].add(current_name)
            elif can_generate_dependencies and (
                extracted_ns_name.domain != extracted_current_name.domain or
                extracted_ns_name.suffix != extracted_current_name.suffix
            ):
                # Add name to active_resolutions, this will prevent it
                # from being reresolved in a cyclic dependency
                self.active_resolutions.add(ns_name_sld)
                if can_generate_nodes:
                    # Create or used prior ns_node for preserving
                    # hierarchical relationships in ns_name reresolution
                    if ns_name in node_nameservers:
                        ns_node = node_nameservers[ns_name]
                    else:
                        node_type = Node.infer_node_type(ns_name, is_ns=True)
                        ns_node = node_list.create_node(ns_name, node_type)
                        ns_node.is_public_suffix = is_public_suffix
                else:
                    ns_node = None
                # Gather dependencies and ips for for ns_name
                ns_name_auth_ns = await self.map_name(
                    original_name=ns_name,
                    dependencies=dependencies,
                    prefix=prefix,
                    is_ns=True,
                    current_node=ns_node,
                    node_list=node_list
                )
                reresolved_ns = ns_name_auth_ns.get(ns_name, None)
                if reresolved_ns is not None:
                    # If reresolution is successful then add to auth_ns
                    auth_ns[ns_name] = reresolved_ns.copy()
            # Add the nameserver-ip relationships to the node data
            if ns_name in node_nameservers and ns_name in auth_ns:
                for ip in auth_ns[ns_name]:
                    node_type = Node.infer_node_type(ip)
                    ip_node = node_list.create_node(ip, node_type)
                    node_nameservers[ns_name].trusts(ip_node, node_trust_type)
        return auth_ns

    async def map_name(
        self,
        original_name: str,
        dependencies: defaultdict(set),
        prefix: str = "",
        name: str = None,
        is_ns: bool = False,
        current_node: Node = None,
        node_list: NodeList = None
    ) -> dict:
        '''Recursively resolve a given hostname

        Args:
            original_name: The target hostname at the end of resolution
            dependencies: Stores a host's ns, tld, etc. dependencies, as
                well as any hazardous or misconfigured domains.
            prefix (optional): Defaults to "". Used primarily to
                differentiate between dependencies as a result of
                hostnames above and below the public suffix level.
            is_ns (optional): Defaults to False. If True, indicates that
                name is a nameserver found in a prior NS record.
            name (optional): Defaults to None. If set, map will target
                queries to name rather than original_name. Used
                primarily for Q-name minimization.
            current_node (optional): Defaults to None. The Node
                referring to name.
            node_list (optional): Defaults to None. The NodeList will be
                used to store all hierarchial dependency data.

        Returns:
            A dict containing a list of nameservers and corresponding ip
            addresses that are authoritative for a given hostname
        '''

        # If current_node and node_list are both set, add current_node
        # to node_list
        can_generate_nodes = current_node and node_list
        if can_generate_nodes:
            node_list.add(current_node)
        # Initialize auth_ns to store the authoritative nameservers to
        # query in each iteration
        auth_ns = None
        # When dependencies is empty from first creation, add
        # QuerySummaryLists for misconfigured and hazardous domains
        if isinstance(dependencies, defaultdict):
            if len(dependencies) == 0:
                misconfigured_domains = defaultdict(QuerySummaryList)
                dependencies['misconfigured_domains'] = misconfigured_domains
                hazardous_domains = QuerySummaryList()
                dependencies['hazardous_domains'] = hazardous_domains
            else:
                misconfigured_domains = dependencies['misconfigured_domains']
                azardous_domains = dependencies['hazardous_domains']
        # If name is not set, set name to original_name
        if not name:
            original_name = format_hostname(original_name)
            name = original_name
        # Split domain and suffix by periods and remove any empty
        # strings
        name_parts = list(filter(None, name.split('.')))
        extracted_name = extract(name)
        # Return cached past resolutions to prevent cyclic dependencies
        # and reduce queries
        if name in self.past_resolutions:
            return self.past_resolutions[name]

        # If name is only tld or '.'
        isTLD = len(name_parts) <= 1
        # If extracted_name doesn't have a domain then name must be a
        # public suffix
        if extracted_name.domain == '':
            prefix = "ps_"
        if isTLD:
            # Base case: If name is tld, then select a rootserver to use
            # as the authoritative ns
            auth_ns = self.get_root_server()
        else:
            # Create name from every part of current name except first
            # (ex. ns1.example.com -> example.com)
            superdomain = f"{'.'.join(name_parts[1:])}."
            superdomain_node = None
            if current_node:
                node_type = Node.infer_node_type(superdomain)
                superdomain_node = node_list.create_node(superdomain, node_type)
                current_node.trusts(superdomain_node, "provisioning")
            # These are the authoritative nameservers from the super
            # domain (ie. com => a.gtld-servers.net => google.com)
            auth_ns = await self.map_name(
                name=superdomain,
                dependencies=dependencies,
                prefix=prefix,
                original_name=original_name,
                current_node=superdomain_node,
                node_list=node_list
            )

        # Authoritative nameserver querying split into two parts: First
        # query the authoritative nameservers for the superdomain to get
        # the authoritative nameservers for the domain, then querying
        # process repeats with the authoritative nameservers for the
        # domain to get the final set of authoritative nameservers
        for i in range(2):
            node_trust_type = "parent" if i == 0 else "child"
            new_auth_ns = defaultdict(set)
            query_response_list = []
            # Flag to detect if atleast one nameserver did not timeout
            has_valid_response = False
            # Flag to check if all responding nameservers have an RCODE
            # of 3 (NXDOMAIN);
            all_nxdomain = True
            # Flag to check if all responding nameservers have an RCODE
            # of 0 (NOERROR), but no records are returned
            empty_nonterminal = True
            # List of compiled ip, nameserver, ns_node tuples compiled
            # from all nameservers in auth_ns
            ip_list = []
            # Query name for each ip for each ns in auth_ns
            for nameserver, ip_set in auth_ns.items():
                nameserver_node = node_list.create_node(nameserver,
                                                        "nameserver")
                for ip in ip_set:
                    node_type = Node.infer_node_type(ip)
                    nameserver_ip_node = node_list.create_node(ip, node_type)
                    nameserver_node.trusts(nameserver_ip_node, node_trust_type)
                    ip_list.append((ip, nameserver, nameserver_node))

            query_requests = []
            # Start query for each ip in ip_list concurrently
            for ip, nameserver, nameserver_node in ip_list:
                query_name = name
                dns_query = self.pydns.query(domain=query_name, nameserver=ip)
                query_requests.append(dns_query)
            query_responses = await asyncio.gather(*query_requests)
            query_response_list += query_responses
            for count, record in enumerate(ip_list):
                # Unpack ip_list record
                ip, nameserver, nameserver_node = record
                query_name = name
                query_response = query_responses[count]
                records = query_response.data
                # If records are not returned, perform additional checks
                # to see if query timed out or returned NXDOMAIN,
                # Else set NXDOMAIN  flag to false and valid reponse
                # flag to true
                if len(records) == 0:
                    ns_timed_out = "timeout" in query_response.rcodes
                    if not ns_timed_out:
                        has_valid_response = True
                        # Flag to check if current response is NXDOMAIN
                        nxdomain = query_response.rcodes['NS'] == 3
                        if not nxdomain:
                            all_nxdomain = False
                            # If RCODE is 0 (NOERROR) then recycle
                            # current ip address for next set of queries
                            if query_response.rcodes['NS'] == 0:
                                current_node.trusts(nameserver_node, node_trust_type)
                                new_auth_ns[nameserver].add(ip)
                                continue
                            else:
                                # If rcode is not NOERROR then can't be
                                # empty nonterminal
                                empty_nonterminal = False
                            # Since the nameserver hasn't timed out or
                            # returned NXDOMAIN, if the current name
                            # isn't the full hostname, repeat the query
                            # with the full hostname
                            if name != original_name:
                                query_name = original_name
                                query_response = await self.pydns.query(
                                    domain=query_name,
                                    nameserver=ip
                                )
                                query_response_list.append(query_response)
                                records = query_response.data
                                if len(records) == 0:
                                    ns_timed_out = "timeout" in query_response.rcodes
                                    if not ns_timed_out and query_response.rcodes['NS'] == 0:
                                        new_auth_ns[nameserver].add(ip)
                                        current_node.trusts(nameserver_node, node_trust_type)
                                        continue
                        else:
                            # If rcode is nxdomain then can't be empty
                            # nonterminal
                            empty_nonterminal = False
                else:
                    has_valid_response = True
                    all_nxdomain = False
                    empty_nonterminal = False

                # Compile returned records into dictionary of
                # authoritative nameservers and their corresponding ip
                # addresses
                parsed_records = await self._parse_records(
                    query_name,
                    records,
                    dependencies if not isTLD else None, prefix,
                    is_ns=is_ns,
                    current_node=current_node,
                    node_list=node_list,
                    node_trust_type=node_trust_type
                )
                # If one of the returned nameservers is '.' mark as
                # invalid NS record data misconfiguration
                if '.' in parsed_records:
                    response_summary = QuerySummary(
                        name=name,
                        rcodes=query_response.rcodes,
                        nameserver=query_response.nameserver
                    )
                    misconfigured_domains['invalid_ns_record'].add(response_summary)
                # Add current set parsed records to dictionary of parsed
                # records
                new_auth_ns.update(parsed_records)
            # If auth_ns is still empty => query returned no nameservers
            # so domain is hazardous, unless a cyclic dependency has
            # occurred, in which case nameserver will be added to
            # nonhazardous domains Else if empty_nonterminal flag is
            # still set, mark current node as empty nonterminal
            if has_valid_response and all_nxdomain and len(new_auth_ns) == 0 \
                    and name not in dependencies['nonhazardous_domains']:
                # If error on first itereation and name is not ip add
                # name to dependencies hazardous set
                # Else add name to misconfiguration set for missing ns
                # records
                if i == 0:
                    if name_parts[-1].isdigit():
                        current_node.is_misconfigured = True
                        current_node.misconfigurations.add("ip_ns_records")
                        summary_target = misconfigured_domains['ip_ns_records']
                    else:
                        current_node.is_hazardous = True
                        summary_target = hazardous_domains
                else:
                    current_node.is_misconfigured = True
                    summary_target = misconfigured_domains['missing_ns_records']
                    current_node.misconfigurations.add("missing_ns_records")
                # Add the query details to the summary_target
                for query_response in query_response_list:
                    response_summary = QuerySummary(
                        name=name,
                        rcodes=query_response.rcodes,
                        nameserver=query_response.nameserver
                    )
                    summary_target.add(response_summary)
                # Add sld/tld data for name to dependencies in case the
                # lack of records causes _parsed_records to have never
                # run for the current hostname, so that data was never
                # collected
                self._extract_hostname_dependencies(name, dependencies, prefix, is_ns=is_ns)
                # Break iteration since is new_auth_ns is empty, no
                # further resolutions can be made
                break
            elif empty_nonterminal:
                current_node.is_empty_nonterminal = True
            auth_ns = new_auth_ns
        # Remove name from active_resolutions to end the hold on it
        # being reresolved
        self.active_resolutions.discard(name)
        # Add to past_resolutions so that reresolutions hit the cache
        # rather than triggering another cyclic dependency
        self.past_resolutions[name] = new_auth_ns
        return new_auth_ns

    async def get_host_dependencies(
        self,
        name: str,
        is_ns: bool = False,
        db_json: bool = False,
        db_rdf: bool = False,
        version: str = None
    ) -> dict:
        '''Get all dependencies for a hostname, as well as any hazardous
        or misconfigured hostnames

        Args:
            name: hostname to gather dependencies for
            is_ns (optional): Defaults to False. If True, will treat the
                given hostname as a nameserver for purposes of
                generating nodes and parsing RRsets
            db_json (optional): Defaults to False. If True, will also
                return a JSON serializable dictonary containing the
                nodelist data
            db_rdf (optional): Defaults to False. If True, will also
                return a string of RDF N-Quad mutations representing the
                nodelist
            version (optional): Defaults to None. If None, the
                versioning key will be set to the RFC 1339 timestamp at
                the beginning of the crawl. Versioning key will be used
                to label facets on uid predicates in the nodelist.

        Returns:
            If db_json and db_rdf are both False, returns a dict
            containing all the ns, tld, sld, etc. dependencies for name,
            If db_json is True with also return a json version of the
            nodelist in the form {'dependencies':data, 'json':json}
            If db_rdf is True with also return a rdf version of the
            nodelist in the form {'dependencies':data, 'rdf':rdf}
        '''

        # Reset nameserver_ip cache at the beginning of each crawl
        self.nameserver_ip = defaultdict(set, self.root_servers)
        # Default version to timestamp at start of crawl
        if not version:
            version = self.get_timestamp()
        # Create nodelist for crawl and root node to represent the
        # target name
        node_list = NodeList(version=version)
        node_type = Node.infer_node_type(name, is_ns)
        node = node_list.create_node(name=name, node_type=node_type)
        # Initialize the dictionary to store the raw dependency data
        dependencies = defaultdict(set)
        auth_ns = await self.map_name(
            name, dependencies,
            is_ns=is_ns,
            current_node=node,
            node_list=node_list
        )
        # Initialize the dictionary to store the formatted dependency
        # data
        host_dependencies = {"query": name}
        # Copy over query data for misconfigured and hazardous domains
        host_dependencies['misconfigured_domains'] = {}
        for k, v in dependencies['misconfigured_domains'].items():
            host_dependencies['misconfigured_domains'][k] = v.queries
        host_dependencies['hazardous_domains'] = dependencies['hazardous_domains'].queries
        fixed_host_dependencies_fields = [
            'ns',
            'ipv4',
            'ipv6',
            'tld',
            'sld',
            'ps_ns',
            'ps_ipv4',
            'ps_ipv6',
            'ps_tld',
            'ps_sld',
        ]
        for field in fixed_host_dependencies_fields:
            # Add raw dependency data to host_dependencies, casting to
            # list to make the data JSON serializable and sorting.
            host_dependencies[field] = sorted(list(dependencies[field]))
        if db_json or db_rdf:
            response = {'dependencies': host_dependencies}
            if db_json:
                response['json'] = node_list.json()
            if db_rdf:
                response['rdf'] = node_list.rdf()
            return response
        return host_dependencies
