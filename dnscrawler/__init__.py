import os

from dnscrawler.db import DatabaseConnection
from dnscrawler.dnsresolver import DNSResolver
from dnscrawler.pydns import PyDNS, SOCKSProxy

path = os.path.dirname(os.path.realpath(__file__))


def load_schema():
    return open(f"{path}/schema.txt", "r")
