import subprocess
import random
def query(domain,nameserver):
    response = subprocess.call(["dig",nameserver,"-q",domain,"-t","NS","+nostats","+nocomments","+noall","+authority"])
    print(response)

def queryRoot(domain):
    root_nameserver = ["a.root-servers.net","b.root-servers.net","c.root-servers.net",
    "d.root-servers.net","e.root-servers.net","f.root-servers.net","g.root-servers.net","h.root-servers.net",
    "i.root-servers.net","j.root-servers.net","k.root-servers.net","l.root-servers.net"]
    query(domain,random.choice(root_nameserver))