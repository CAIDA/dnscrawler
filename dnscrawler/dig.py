from subprocess import Popen, PIPE,call
import constants
from random import choice
def query(domain,nameserver,record_types):
    # Either use aliased record names or passed record name in comparison
    # Start dig subprocess
    process = Popen(["dig","@"+nameserver,"-q",domain,"-t","ANY",
        "+nostats","+nocomments","+tries="+constants.DIG_TRIES,"+time="+constants.DIG_TIMEOUT],
        stdout=PIPE, stderr=PIPE)
    stdout,stderr = map(lambda val:val.decode('utf-8'), process.communicate())
    # Split dig reponse at new line
    response = stdout.splitlines()
    if(len(stderr)>0):
        raise Exception(stderr)
    # Return dig response as dict
    data = {}
    for row in response:
        if len(row)>0 and row[0]!=";":
            filtered_row = row.split()
            # Index by returned result
            if filtered_row[3] in record_types or "ANY" in record_types:
                data[filtered_row[4]]={
                    "name":filtered_row[0],
                    "ttl":filtered_row[1],
                    "class":filtered_row[2],
                    "type":filtered_row[3],
                    "data":filtered_row[4],
                }
    return data

def query_root(domain,record_type):
    root_nameserver = ["a.root-servers.net","b.root-servers.net","c.root-servers.net",
    "d.root-servers.net","e.root-servers.net","f.root-servers.net","g.root-servers.net","h.root-servers.net",
    "i.root-servers.net","j.root-servers.net","k.root-servers.net","l.root-servers.net"]
    return query(domain,choice(root_nameserver),record_type)