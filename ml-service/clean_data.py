import pandas as pd

df = pd.read_csv("data.csv", encoding="utf-8-sig")

df.columns = df.columns.str.strip()

df = df.rename(columns={"type": "label"})

df["label"] = df["label"].astype(str).str.lower().map({
    "legitimate": 0,
    "benign": 0,
    "phishing": 1,
    "malware": 1,
    "defacement": 1
})

df = df.dropna()
df = df[["url", "label"]]

df.to_csv("data_clean.csv", index=False)

print("DONE")