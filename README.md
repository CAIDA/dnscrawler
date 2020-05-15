# DNSCrawler

## `dnscrawler.print_zone_data(domain)`
Sample output:
```sh
google.com.  NS  ns2.google.com.
google.com.  NS  ns1.google.com.
google.com.  NS  ns3.google.com.
google.com.  NS  ns4.google.com.
ns2.google.com.  AAAA  2001:4860:4802:34::a
ns2.google.com.  A  216.239.34.10
ns1.google.com.  AAAA  2001:4860:4802:32::a
ns1.google.com.  A  216.239.32.10
ns3.google.com.  AAAA  2001:4860:4802:36::a
ns3.google.com.  A  216.239.36.10
ns4.google.com.  AAAA  2001:4860:4802:38::a
ns4.google.com.  A  216.239.38.10
```

## `dnscrawler.print_zone_json(domain)`
Sample output:
```json
[
    {
        "name": "google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "NS",
        "data": "ns2.google.com."
    },
    {
        "name": "google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "NS",
        "data": "ns1.google.com."
    },
    {
        "name": "google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "NS",
        "data": "ns3.google.com."
    },
    {
        "name": "google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "NS",
        "data": "ns4.google.com."
    },
    {
        "name": "ns2.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "AAAA",
        "data": "2001:4860:4802:34::a"
    },
    {
        "name": "ns2.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "A",
        "data": "216.239.34.10"
    },
    {
        "name": "ns1.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "AAAA",
        "data": "2001:4860:4802:32::a"
    },
    {
        "name": "ns1.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "A",
        "data": "216.239.32.10"
    },
    {
    "name": "ns3.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "AAAA",
        "data": "2001:4860:4802:36::a"
    },
    {
        "name": "ns3.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "A",
        "data": "216.239.36.10"
    },
    {
        "name": "ns4.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "AAAA",
        "data": "2001:4860:4802:38::a"
    },
    {
        "name": "ns4.google.com.",
        "ttl": "172800",
        "class": "IN",
        "type": "A",
        "data": "216.239.38.10"
    }
]
```