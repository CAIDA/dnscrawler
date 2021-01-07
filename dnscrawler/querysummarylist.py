from collections import defaultdict


class QuerySummaryList:
    def __init__(self):
        self.queries = defaultdict(list)

    def add(self, query_summary):
        name = query_summary.name
        summary_dict = dict(query_summary)
        del summary_dict['name']
        self.queries[query_summary.name].append(summary_dict)
