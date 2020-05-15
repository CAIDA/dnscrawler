from subprocess import Popen, PIPE,call
from . import constants
from random import choice
from functools import lru_cache

def dig_response(domain,nameserver):
    process = Popen(["dig","@"+nameserver,"-q",domain,"-t","ANY",
        "+nostats","+nocomments","+tries="+constants.DIG_TRIES,"+time="+constants.DIG_TIMEOUT],
        stdout=PIPE, stderr=PIPE)
    return map(lambda val:val.decode('utf-8'), process.communicate())

def query(domain,nameserver,record_types):
    # Split dig reponse at new line
    stdout, stderr = dig_response(domain,nameserver)
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


@lru_cache(maxsize=128)
def query_root(domain,record_type):
    root_nameserver = ["a.root-servers.net","b.root-servers.net","c.root-servers.net",
    "d.root-servers.net","e.root-servers.net","f.root-servers.net","g.root-servers.net","h.root-servers.net",
    "i.root-servers.net","j.root-servers.net","k.root-servers.net","l.root-servers.net"]
    return query(domain,choice(root_nameserver),record_type)