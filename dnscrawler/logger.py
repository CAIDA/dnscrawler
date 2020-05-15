import json
def log(obj):
    print(json.dumps(obj,indent=4))

def log_records(records):
    for record in records:
        print(record['name'],end="\t")
        print(record['type'],end="\t")
        print(record['data'])

def log_jsonld(arr):
    for element in arr:
        print(json.dumps(element))
