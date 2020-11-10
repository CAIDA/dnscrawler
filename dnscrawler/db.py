import datetime
import json

import pydgraph

class DatabaseConnection:
    def __init__(self, conn):
        self.client_stub =  pydgraph.DgraphClientStub(conn)
        self.client = pydgraph.DgraphClient(self.client_stub)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self.client_stub.close()

    def query(self, query, variables):
        res = self.client.txn(read_only=True).query(query, variables=variables)
        data = json.loads(res.json)
        return data

    def create(self, data):
        response = self.__txn(lambda txn: txn.mutate(set_obj=data))
        return response

    def delete(self, uid):
        data = {'uid':uid}
        response = self.__txn(lambda txn: txn.mutate(del_obj=data))
        return response

    def set_schema(self, schema):
        return self.client.alter(pydgraph.Operation(schema=schema))

    def drop_all(self):
        return self.client.alter(pydgraph.Operation(drop_all=True))

    def __txn(self, handler):
        txn = self.client.txn()
        res = None
        try:
            res = handler(txn)
            txn.commit()
        finally:
            txn.discard()
        return json.loads(res.json) if len(res.json) > 0 else str(res)