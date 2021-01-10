import sys
sys.path.append("../")

from objsize import get_deep_size

from dnscrawler.nsset import NSSet
from dnscrawler.stringreferencecache import StringReferenceCache

if __name__ == "__main__":

    data =  {'ns6.googledomains.com.': {'216.239.34.10', '2001:4860:4802:34::a'}, 'ns8.googledomains.com.': {'2001:4860:4802:38::a', '216.239.38.10'}, 'ns5.googledomains.com.': {'2001:4860:4802:32::a', '216.239.32.10'}, 'ns7.googledomains.com.': {'2001:4860:4802:36::a', '216.239.36.10'}, 'ns3.googledomains.com.': {'216.239.34.10', '2001:4860:4802:34::a'}, 'ns4.googledomains.com.': {'2001:4860:4802:38::a', '216.239.38.10'}, 'ns1.googledomains.com.': {'2001:4860:4802:32::a', '216.239.32.10'}, 'ns2.googledomains.com.': {'2001:4860:4802:36::a', '216.239.36.10'},}
    data2 =  {'abc.googledomains.com.': {'216.239.34.10', '2001:4860:4802:34::a'}, 'ns8.googledomains.com.': {'2001:4860:4802:38::a', '216.239.38.10'}, 'ns5.googledomains.com.': {'2001:4860:4802:32::a', '216.239.32.10'}, 'ns7.googledomains.com.': {'2001:4860:4802:36::a', '216.239.36.10'}, 'ns3.googledomains.com.': {'216.239.34.10', '2001:4860:4802:34::a'}, 'ns4.googledomains.com.': {'2001:4860:4802:38::a', '216.239.38.10'}, 'ns1.googledomains.com.': {'2001:4860:4802:32::a', '216.239.32.10'}, 'ns2.googledomains.com.': {'2001:4860:4802:36::a', '216.239.36.10'},}
    ns = NSSet(data)
    ns2 = NSSet(data2)
    cache = StringReferenceCache(capacity=None)
    print("Both empty")
    print(cache.stats())
    print(cache.str_to_reference)
    cache.set("google.com", ns)
    cache.set("asd.com", ns.copy())
    print("Keys 2, references 2")
    print(cache.stats())
    print(cache.str_to_reference)
    cache.set("dfg.com", ns2)
    print("Keys 3, references 2, 1")
    print(cache.stats())
    print(cache.str_to_reference)
    cache.set("dqwe.com", ns2.copy())
    print("Keys 3, references 1, 2")
    print(cache.stats())
    print(cache.str_to_reference)
    cache.set("dqw1e.com", ns2.copy())
    print("Keys 3, references 0, 3")
    print(cache.stats())
    print(cache.str_to_reference)