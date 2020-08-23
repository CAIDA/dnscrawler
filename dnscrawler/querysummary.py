class QuerySummary:
    def __init__(self, name, nameserver, rcodes):
        self.name = name.lower()
        self.rcodes = rcodes
        self.nameserver = nameserver
    def __eq__(self, other):
        return self.name == other.name
    def __hash__(self):
        return self.name.__hash__()
    def __iter__(self):
        yield "name", self.name
        yield "nameserver", self.nameserver
        yield "rcodes", self.rcodes