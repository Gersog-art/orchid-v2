#!/usr/bin/env python3
"""Обучение ML моделей на реальных данных из БД"""
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os
import re

print("=" * 60)
print("ОБУЧЕНИЕ ML МОДЕЛЕЙ НА РЕАЛЬНЫХ ДАННЫХ")
print("=" * 60)

# Загружаем данные
df = pd.read_csv('training_data/real_attacks.csv')
print(f"\n✅ Загружено {len(df)} записей")

# Функция извлечения признаков
def extract_features(df):
    features = pd.DataFrame()
    
    # Длина запроса
    features['payload_length'] = df['payload'].fillna('').str.len()
    features['endpoint_length'] = df['endpoint'].fillna('').str.len()
    
    # SQL ключевые слова
    sql_keywords = ['SELECT', 'UNION', 'DROP', 'DELETE', 'INSERT', 'UPDATE', 'OR', 'AND', '--', ';']
    features['sql_keywords'] = df['payload'].fillna('').apply(
        lambda x: sum(1 for kw in sql_keywords if kw.lower() in x.lower())
    )
    
    # XSS паттерны
    features['xss_patterns'] = df['payload'].fillna('').apply(
        lambda x: len(re.findall(r'<script|alert\(|onerror|onload|javascript:', x.lower()))
    )
    
    # LFI паттерны
    features['lfi_patterns'] = df['payload'].fillna('').apply(
        lambda x: len(re.findall(r'\.\./|\.\.\\|/etc/passwd|/etc/shadow', x))
    )
    
    # Специальные символы
    features['special_chars'] = df['payload'].fillna('').apply(
        lambda x: len(re.findall(r"['\";()=]", x))
    )
    
    # Цифры
    features['digits'] = df['payload'].fillna('').str.count(r'\d')
    
    # Кодировка типа атаки
    le = LabelEncoder()
    df['attack_type_encoded'] = le.fit_transform(df['attack_type'].fillna('unknown'))
    
    return features, le

print("\nИзвлечение признаков...")
X, label_encoder = extract_features(df)
y = df['attack_type_encoded']

print(f"✅ Признаков: {X.shape[1]}")

# Разделение на train/test
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scaler
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 1. Isolation Forest (для детекции аномалий)
print("\n" + "=" * 40)
print("1. Обучение Isolation Forest...")
iso_model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, n_jobs=-1)
iso_model.fit(X_train_scaled)
print("✅ Isolation Forest сохранён")

# 2. Random Forest (для классификации)
print("\n" + "=" * 40)
print("2. Обучение Random Forest...")
rf_model = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
rf_model.fit(X_train_scaled, y_train)

# Оценка
y_pred = rf_model.predict(X_test_scaled)
from sklearn.metrics import classification_report, accuracy_score
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Точность Random Forest: {accuracy:.4f}")
print("\nОтчёт классификации:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))

# 3. Gradient Boosting (новый!)
print("\n" + "=" * 40)
print("3. Обучение Gradient Boosting...")
gb_model = GradientBoostingClassifier(n_estimators=150, max_depth=10, random_state=42)
gb_model.fit(X_train_scaled, y_train)

gb_pred = gb_model.predict(X_test_scaled)
gb_accuracy = accuracy_score(y_test, gb_pred)
print(f"✅ Точность Gradient Boosting: {gb_accuracy:.4f}")

# Сохранение моделей
print("\n" + "=" * 40)
print("Сохранение моделей...")
os.makedirs('models', exist_ok=True)

joblib.dump(iso_model, 'models/isolation_forest_real.joblib')
joblib.dump(rf_model, 'models/random_forest_real.joblib')
joblib.dump(gb_model, 'models/gradient_boosting_real.joblib')
joblib.dump(scaler, 'models/scaler.joblib')
joblib.dump(label_encoder, 'models/label_encoder.joblib')

print("✅ Все модели сохранены в models/")

# Топ признаков
print("\n" + "=" * 40)
print("Топ-10 важных признаков (Random Forest):")
importances = pd.DataFrame({
    'feature': X.columns,
    'importance': rf_model.feature_importances_
}).sort_values('importance', ascending=False)
print(importances.head(10))

print("\n" + "=" * 60)
print("ОБУЧЕНИЕ ЗАВЕРШЕНО!")
print("=" * 60)
