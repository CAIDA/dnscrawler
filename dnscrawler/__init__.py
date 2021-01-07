from .dnsresolver import DNSResolver
from .db import DatabaseConnection
import os
from .pydns import PyDNS

path = os.path.dirname(os.path.realpath(__file__))


def load_schema():
    return open(f"{path}/schema.txt", "r")
