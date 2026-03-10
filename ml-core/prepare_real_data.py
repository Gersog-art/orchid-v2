#!/usr/bin/env python3
import sqlite3
import pandas as pd
import os

db_path = '../data/attacks.db'
conn = sqlite3.connect(db_path)

query = """
SELECT attack_type, payload, endpoint, http_method, request_body, source_ip
FROM attacks 
WHERE attack_type IN ('sqli','xss','lfi','rce','xxe','brute','normal','unknown_anomaly')
LIMIT 50000
"""
df = pd.read_sql_query(query, conn)
conn.close()

print(f"Загружено {len(df)} записей для обучения")
print(f"\nРаспределение по типам:")
print(df['attack_type'].value_counts())

os.makedirs('training_data', exist_ok=True)
df.to_csv('training_data/real_attacks.csv', index=False)
print(f"\nДанные сохранены в training_data/real_attacks.csv")
