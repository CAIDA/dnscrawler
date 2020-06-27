import pandas as pd
df = pd.read_json("./data/ns_data.jsonl",lines=True)
print(df);
