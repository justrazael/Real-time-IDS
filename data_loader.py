import pandas as pd
import json
import os

def load_ids_logs(file_path):
    """
    Loads IDS output files in CSV or JSON format into a pandas DataFrame.
    Ensures compatibility with common IDS log structures.
    """

    if not os.path.exists(file_path):
        print(f"[Error] File not found: {file_path}")
        return None

    try:
        # Load CSV logs
        if file_path.endswith(".csv"):
            print(f"[INFO] Loading CSV file: {file_path}")
            df = pd.read_csv(file_path)
        
        # Load JSON logs
        elif file_path.endswith(".json"):
            print(f"[INFO] Loading JSON file: {file_path}")
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            df = pd.json_normalize(data)  # Flattens nested JSON
        
        else:
            print(f"[Error] Unsupported file type: {file_path}")
            return None

        print(f"[INFO] ✅ Successfully loaded {len(df)} records.")
        print(f"[INFO] 🧩 Columns detected: {list(df.columns)}")


        # Normalize column names (to handle different IDS formats)
        df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')

        return df

    except Exception as e:
        print(f"[Error] Failed to parse {file_path}: {e}")
        return None


# Example usage
if __name__ == "__main__":
    test_csv = "dataset/TimeBasedFeatures-Dataset-15s-VPN.csv"  # replace with your file path
    logs_df = load_ids_logs(test_csv)

    if logs_df is not None:
        print("\n✅ Preview of loaded data:")
        print(logs_df.head())

