from io import StringIO 
import multiprocessing as mp
import json
import sys
import shutil
import os
sys.path.append("../")
from dnscrawler import print_zone_data,print_zone_json,get_domain_dict
from dnscrawler.logger import log
from glob import glob

def json_nameserver_file(nameserver,output_dir):
    filename = nameserver.replace(".","")
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    filepath = output_dir+"/"+filename+".json"
    if not os.path.exists(filepath):
        domain_dict = get_domain_dict(nameserver)
        f = open(filepath,"w")
        f.write(json.dumps(domain_dict))
        f.close()


def compile_nameserver_json(source_file,target_file):
    nsfile = open(source_file,"r")
    nameservers = nsfile.read().splitlines()
    nsfile.close()
    pool = mp.Pool(mp.cpu_count())
    target_dir = os.path.dirname(target_file)
    for nameserver in nameservers:
        pool.apply_async(json_nameserver_file, args=(nameserver,target_dir+"/temp"))
    pool.close()
    pool.join()
    with open(target_file,"wb") as outfile:
        for filename in glob(target_dir+"/temp/*.json"):
            with open(filename, "rb") as infile:
                outfile.write(infile.read())
                outfile.write('\n'.encode('utf-8'))
                infile.close()

if __name__ == "__main__":
    compile_nameserver_json("ns.txt","data/ns_data.jsonl")