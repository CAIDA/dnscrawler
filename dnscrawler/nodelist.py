class NodeList:
    def __init__(self, xids=None):
        self.nodes = {}
        self.xids = xids or set();

    def add(self, node):
        self.xids.add(node.xid())
        if node.xid() not in self.nodes:
            self.nodes[node.xid()] = node
        else:
            # Merge old and new nodes
            oldNode = self.nodes[node.xid()];
            oldNode.trusts.merge(node.trusts)
            oldNode.is_hazardous = oldNode.is_hazardous or node.is_hazardous;
            oldNode.is_misconfigured = oldNode.is_misconfigured or node.is_misconfigured;
            oldNode.misconfigurations.update(node.misconfigurations);
        return node

    def merge(self, other):
        for node in other.nodes.values():
            self.add(node)
        other.nodes = self.nodes
        other.xids = self.xids

    def json(self):
        return [node.json() for node in self.nodes.values()]
