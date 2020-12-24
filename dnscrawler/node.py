from ipaddress import ip_address
from collections import defaultdict
from tldextract import extract
from traceback import print_stack
if __name__ == "node":
    from nodelist import NodeList
else:
    from .nodelist import NodeList

# Lookup table for DNS node types and corresponding prefixes
node_type_prefix = {
    'nameserver':"NSR",
    'ipv4':"IP4",
    'ipv6':"IP6",
    "domain":"DMN",
    "subdomain":"SDN",
    "tld":"TLD",
    "public_suffix_tld":"PS_TLD",
    # "public_suffix_nameserver":"PS_NS",
    # "public_suffix_ipv4":"PS_IP4",
    # "public_suffix_ipv6":"PS_IP6",
    # "public_suffix_domain":"PS_DMN",
    # "public_suffix_subdomain":"PS_SDN",
}

class Node:
    def __init__(self, name, node_type='nameserver', root_nodelist=None):
        self.type = node_type
        self.version = root_nodelist.version if root_nodelist else None
        self.is_hazardous = False
        self.is_misconfigured = False
        self.is_empty_nonterminal = False
        self.is_public_suffix = False
        self.misconfigurations = set()
        self._trusts = defaultdict(NodeList)
        name = name.lower()
        if "ip" not in self.type:
            # Add trailing period to all hostnames
            if name[-1] != '.':
                name = f"{name}."

            # Add parent domain bidirectional relationship
            # If node is a subdomain then parent is the public suffix domain
            # Elif node is a public suffix domain then the parent is public suffix
            # Else parent is public suffix so parent is superdomain
            extracted_name = extract(name)
            if extracted_name.subdomain != "":
                parent_name = f"{extracted_name.domain}.{extracted_name.suffix}."
            elif extracted_name.domain != "":
                parent_name = f"{extracted_name.suffix}."
            else:
                name_parts = [part for part in name.split('.') if len(part) > 0]
                # If node has more than one label then parent is superdomain
                # Else node is tld, and has no bidirectional parent
                if len(name_parts) > 1:
                    parent_name = f"{'.'.join(name_parts[1:])}."
                else:
                    parent_name = name
            parent_type = self.infer_node_type(parent_name)
            # If parent name is not name (node is not the parent domain), add bidirectional trust
            if name != parent_name:
                if root_nodelist:
                    parent_node = root_nodelist.create_node(parent_name, parent_type)
                else:
                    parent_node = Node(parent_name, parent_type)
                self.trusts(parent_node, "provisioning")
        self.name = name

    # Generate external id for node
    def xid(self):
        return f"{node_type_prefix[self.type]}${self.name}"

    # Generate internal uid replacement for node
    def uid(self):
        return f"_:{self.xid()}"

    def __repr__(self):
        return self.xid()

    # Function to guess node type if unknown
    @staticmethod
    def infer_node_type(name, is_ns=False):
        name_parts = [part for part in name.split('.') if len(part) > 0]
        if is_ns:
            return "nameserver"
        # Differentiate between a tld and ipv6 through the presence of a ':' 
        elif len(name_parts) == 1 and ":" not in name_parts[0]:
            return "tld"
        else:
            try:
                ip = ip_address(name)
                return f"ipv{ip.version}"
            except:
                extracted_name = extract(name)
                if extracted_name.domain == '':
                    return "public_suffix_tld"
                elif extracted_name.subdomain == '':
                    return "domain"
                else:
                    return "subdomain"


    # Node type getter and setter 
    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if not value in node_type_prefix:
            raise ValueError(f"Node type {value} is not valid")
        self._type = value

    # Function to add trust dependencies
    def trusts(self, node, trust_type="parent"):
        return self._trusts[trust_type].add(node)

    # Generate json serializable dictionary for node
    def json(self, full_data=True):
        if not full_data:
            return {
                'uid':self.uid()
            }
        data = {
            'name':self.name,
            'dgraph.type':self.type,
            'uid':self.uid(),
            'xid':self.xid(),
            'details':[{
                'details|version':self.version,
                'is_empty_nonterminal':self.is_empty_nonterminal,
                'is_hazardous':self.is_hazardous,
                'is_misconfigured':self.is_misconfigured,
                'is_public_suffix':self.is_public_suffix,
                'misconfigurations':list(self.misconfigurations),
                'uid':f"{self.uid()}_details_{self.version}",
                'xid':f"{self.xid()}_details_{self.version}",
            }],
            'trusts':[{
                'uid':f"{self.uid()}_trust_{self.version}",
                'xid':f"{self.xid()}_trust_{self.version}",
            }]
        }
        trusts = data['trusts'][0]
        for key, nodelist in self._trusts.items():
            trusts[key] = nodelist.json(full_data=False)
        data['trusts'][0] = {k:trusts[k] for k in sorted(trusts.keys())}
        filtered_data = {k:data[k] for k in sorted(data.keys()) if data[k] is not False}
        return filtered_data

    # Generate list of n-quad rdf lines for a node
    def rdf(self):
        lines = []
        # Identifiers for Details Node
        details_xid = f"{self.xid()}_details_{self.version}"
        details_uid = f"_:{details_xid}"
        # Identifiers for Trusts Node
        trusts_xid = f"{self.xid()}_trust_{self.version}"
        trusts_uid = f"_:{trusts_xid}"
        # Collection of node predicates of that don't require managing internode edges
        scalar_predicates = [
            {'uid':self.uid(), 'predicates':['name',('dgraph.type',self.type), ('xid',self.xid())]},
            {'uid':details_uid, 'predicates':['is_empty_nonterminal','is_hazardous','is_misconfigured','is_public_suffix', ('xid',details_xid), ('dgraph.type','node_details')]},
            {'uid':trusts_uid, 'predicates':[('xid',trusts_xid), ('dgraph.type','node_trusts')]},
        ]
        for node in scalar_predicates:
            for predicate in node['predicates']:
                predicate_name = predicate[0] if isinstance(predicate, tuple) else predicate
                predicate_value = predicate[1] if isinstance(predicate, tuple) else getattr(self, predicate)
                lines.append(f'<{node["uid"]}> <{predicate_name}> "{predicate_value}" .')
        
        # Add misconfigurations to details node
        for misconfiguration in sorted(list(self.misconfigurations)):
            lines.append(f'<{details_uid}> <misconfiguration> "{misconfiguration}" .')
        # Add trust dependencies to trusts nodes
        for key in sorted(self._trusts.keys()):
            nodelist = self._trusts[key]
            for node in nodelist.sorted_nodes():
                lines.append(f"<{trusts_uid}> <{key}> <{node.uid()}> .")
        # Add relationships between entity node and trust/details nodes
        lines.append(f'<{self.uid()}> <details> <{details_uid}> (first_seen="{self.version}", last_seen="{self.version}") .')
        lines.append(f'<{self.uid()}> <trusts> <{trusts_uid}> (first_seen="{self.version}", last_seen="{self.version}") .')
        return lines
