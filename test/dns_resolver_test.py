import sys
sys.path.append("../")
from dnscrawler import DNSResolver
from dnscrawler.logger import log
import json

if __name__ == "__main__":
    # resolver = DNSResolver([{'addr':"192.172.226.186",'port':1080}])
    resolver = DNSResolver()
    domain_dict = resolver.get_domain_dict("google.com")
    # domain_dict = resolver.get_domain_dict("caag.state.ca.us")
    # domain_dict = resolver.get_domain_dict("kitchengardenstore.com")
    print(json.dumps(domain_dict))

