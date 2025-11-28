# ...existing code...
import os
import pandas as pd
from pandas.errors import EmptyDataError

DATA_PATH = os.path.join("data", "malicious_phish.csv")
OUT_PATH = os.path.join("data", "cleaned_malicious_phish.csv")

def try_read(path):
    try:
        print("Trying default read_csv()")
        df = pd.read_csv(path)
        if not df.empty and df.shape[1] >= 1:
            return df
    except EmptyDataError:
        print("EmptyDataError: file has no columns or is empty.")
    except Exception as e:
        print("read_csv default failed:", repr(e))

    # try common separators
    for sep in [';', '\t', '|', ',']:
        try:
            print(f"Trying sep='{sep}'")
            df = pd.read_csv(path, sep=sep)
            if not df.empty and df.shape[1] >= 1:
                return df
        except Exception:
            pass

    # try without header (assume two columns: url,label)
    try:
        print("Trying header=None with names=['url','label']")
        df = pd.read_csv(path, header=None, names=['url','label'])
        if not df.empty:
            return df
    except Exception:
        pass

    # last resort: show raw lines for manual inspection
    print("Failed to parse CSV — printing first 20 lines for inspection:")
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for i, line in enumerate(f):
            if i >= 20: break
            print(f"{i+1}: {line.rstrip()}")
    return None

if not os.path.exists(DATA_PATH):
    print(f"File not found: {DATA_PATH}")
    raise SystemExit(1)

if os.path.getsize(DATA_PATH) == 0:
    print(f"File is empty: {DATA_PATH}")
    raise SystemExit(1)

df = try_read(DATA_PATH)
if df is None:
    raise SystemExit("Could not read CSV. Fix file or format and retry.")

# Ensure we have url and label columns
if 'label' not in df.columns:
    if df.shape[1] >= 2:
        df.columns = ['url', 'label'] + list(df.columns[2:])
        print("Assigned first two columns to ['url','label']")
    else:
        print("No label column and not enough columns to infer labels.")
        raise SystemExit(1)

# Map labels to numeric values
df['label'] = df['label'].map({
    'benign': 0,
    'phishing': 1,
    'defacement': 1,
    'malware': 1
})

print(df.head())
print(df['label'].value_counts())

df.to_csv(OUT_PATH, index=False)
print(f"\n✅ Cleaned dataset saved as '{OUT_PATH}'")
# ...existing code...



