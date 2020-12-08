# DNSCrawler
* `/run/run.py` handles execution of crawling over a list of hostnames
* `/dnscrawler/dnsresolver.py` handles crawling of a single hostname
* `/run/run_db.py` handles execution of crawling over a list of hostnames and outputs a gzipped json file containing the nodes and their relations for use in a dgraph db
* `/dnscrawler/db_dnsresolver.py` handles crawling of a single hostname and inputs data into local dgraph db
## `DNSResolver.get_domain_dict(domain, is_ns=False, db_json=False)`
* `domain` - hostname to query dependency data for
* `is_ns` - flag to indicate if the initially queried name is a nameserver or not; used to predetermine node types and ip handling behavior when NS records are not available for 4+ part nameservers
* `db_json` - flag to indicate whether a dictionary of node relations is desired in addition to the main dependency dictionary for graph database entry 


```python
get_domain_dict("google.com")
```
```json
{
   "hazardous_domains":[

   ],
   "ns":[
      "ns2.google.com.",
      "ns1.google.com.",
      "ns3.google.com.",
      "ns4.google.com."
   ],
   "ipv4":[
      "216.239.34.10",
      "216.239.32.10",
      "216.239.36.10",
      "216.239.38.10",
      "172.217.4.174"
   ],
   "ipv6":[
      "2001:4860:4802:32::a",
      "2001:4860:4802:34::a",
      "2001:4860:4802:38::a",
      "2607:f8b0:4007:801::200e",
      "2001:4860:4802:36::a"
   ],
   "tld":[
      "com."
   ],
   "sld":[
      "google.com."
   ],
   "ps_ns":[

   ],
   "ps_ipv4":[

   ],
   "ps_ipv6":[

   ],
   "ps_tld":[

   ],
   "ps_sld":[

   ]
}
```
