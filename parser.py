import pandas as pd


def load_logs(file_path):
    df = pd.read_csv(file_path)

    df["timestamp"] = pd.to_datetime(df["timestamp"])

    return df.sort_values("timestamp").reset_index(drop=True)