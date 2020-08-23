from inspect import stack

class Node():
    def __init__(self, val, parent=None):
        self.val = val
        self.parent = parent
    def __repr__(self):
        return self.val
    def __eq__(self, other):
        return self.val == other.val && self.parent == other.parent
    def __hash__(self):
        return (self.val+self.parent).__hash__()
    def __setattr__(self, *args):
        if stack()[1][3] == '__init__':
            object.__setattr__(self, *args)
        else:
            raise TypeError('Cannot modify immutable instance')
    __delattr__ = __setattr__