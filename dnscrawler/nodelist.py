class NodeList:
    def __init__(self, xids=None):
        self.nodes = {}
        self.xids = xids or set();

    def add(self, node):
        self.xids.add
        if node.xid() not in self.nodes:
            self.nodes[node.xid()] = node
        else:
            self.nodes[node.xid()].trusts.merge(node.trusts)
        return node

    def merge(self, other):
        for node in other.nodes.values():
            self.add(node)
