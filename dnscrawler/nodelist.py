class NodeList:
    def __init__(self, xids=None, version=None):
        self.nodes = {}
        self.version = version

    def add(self, node, merged_xids=None, is_public_suffix=False):
        # Preserve child public suffix state
        if is_public_suffix:
            node.is_public_suffix = is_public_suffix

        # If added node's xid is not already in node list,
        # add node to node list, Else merge old and new node
        if not self.contains(node):
            self.nodes[node.xid()] = node
        else:
            # Create set of nodes already merged in current recursive merge
            if not merged_xids:
                merged_xids = set()
            # If node has not already been merged, merge node
            if node.xid() not in merged_xids:
                merged_xids.add(node.xid())
                # Merge old and new nodes
                oldNode = self.nodes[node.xid()]
                # Preserve flags
                oldNode.is_hazardous = oldNode.is_hazardous or node.is_hazardous
                oldNode.is_misconfigured = oldNode.is_misconfigured or node.is_misconfigured
                oldNode.is_public_suffix = oldNode.is_public_suffix or node.is_public_suffix
                oldNode.is_empty_nonterminal = oldNode.is_empty_nonterminal or node.is_empty_nonterminal
                oldNode.misconfigurations.update(node.misconfigurations)
                # Merge each node list between old node
                for key, nodelist in node._trusts.items():
                    oldNode._trusts[key].merge(
                        nodelist, merged_xids, oldNode.is_public_suffix)
        return node

    def contains(self, node):
        return node.xid() in self.nodes

    def merge(self, other, merged_xids=None, is_public_suffix=False):
        for node in other.nodes.values():
            self.add(node, merged_xids, is_public_suffix)
        other.nodes = self.nodes

    def sorted_nodes(self):
        return sorted(self.nodes.values(), key=lambda node: node.xid())

    def json(self, full_data=True):
        return [node.json(full_data) for node in self.sorted_nodes()]

    def rdf(self):
        lines = []
        for node in self.sorted_nodes():
            lines += node.rdf()
        return "\n".join(lines)

    def __repr__(self):
        return str([node.xid() for node in self.sorted_nodes()])

    def create_node(self, *args, **kwargs):
        if __name__ == "nodelist":
            from node import Node
        else:
            from .node import Node
        new_node = Node(*args, **kwargs, root_nodelist=self)
        if self.contains(new_node):
            return self.nodes[new_node.xid()]
        # print(new_node)
        self.add(new_node)
        return new_node
