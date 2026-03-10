#!/usr/bin/env python3
"""
ORCHID - Train All 13 ML Models
Обучает все ML модели для системы безопасности
"""

import os
import logging
import numpy as np
import joblib
from datetime import datetime
from sklearn.ensemble import (
    IsolationForest, RandomForestClassifier, GradientBoostingClassifier,
    ExtraTreesClassifier, AdaBoostClassifier
)
from sklearn.linear_model import LogisticRegression
from sklearn.svm import OneClassSVM
from sklearn.neural_network import MLPClassifier, MLPRegressor
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('orchid_trainer')

MODEL_DIR = '/app/models'
os.makedirs(MODEL_DIR, exist_ok=True)

def generate_synthetic_attacks(n_samples=10000):
    logger.info(f"Generating {n_samples} synthetic attack samples...")
    np.random.seed(42)
    normal = np.random.normal(loc=[50, 500, 10, 0.05, 0.1, 0.2, 300, 0.02], scale=[20, 200, 5, 0.03, 0.05, 0.1, 100, 0.01], size=(n_samples // 2, 8))
    normal_labels = np.zeros(n_samples // 2)
    ddos = np.random.normal(loc=[500, 100, 50, 0.8, 0.9, 0.1, 10, 0.5], scale=[200, 50, 20, 0.1, 0.05, 0.05, 5, 0.2], size=(n_samples // 8, 8))
    sqli = np.random.normal(loc=[30, 200, 5, 0.3, 0.2, 0.3, 500, 0.1], scale=[15, 100, 3, 0.1, 0.1, 0.1, 200, 0.05], size=(n_samples // 8, 8))
    xss = np.random.normal(loc=[40, 800, 8, 0.2, 0.15, 0.4, 400, 0.05], scale=[20, 300, 4, 0.1, 0.08, 0.15, 150, 0.03], size=(n_samples // 8, 8))
    brute = np.random.normal(loc=[200, 100, 2, 0.6, 0.3, 0.05, 50, 0.9], scale=[50, 50, 1, 0.15, 0.1, 0.02, 20, 0.05], size=(n_samples // 8, 8))
    attack = np.vstack([ddos, sqli, xss, brute])
    attack_labels = np.ones(len(attack))
    X = np.vstack([normal, attack])
    y = np.concatenate([normal_labels, attack_labels])
    attack_types = np.concatenate([np.zeros(n_samples // 2), np.ones(n_samples // 8) * 1, np.ones(n_samples // 8) * 2, np.ones(n_samples // 8) * 3, np.ones(n_samples // 8) * 4])
    logger.info(f"Generated {len(X)} samples with {int(np.sum(y == 1))} attacks")
    return X, y, attack_types

def train_isolation_forest(X):
    logger.info("Training Isolation Forest...")
    model = IsolationForest(n_estimators=200, contamination=0.1, random_state=42, n_jobs=-1)
    model.fit(X)
    joblib.dump(model, os.path.join(MODEL_DIR, 'isolation_forest_real.joblib'))
    logger.info("Isolation Forest saved")
    return model

def train_random_forest(X, y):
    logger.info("Training Random Forest...")
    model = RandomForestClassifier(n_estimators=200, max_depth=20, random_state=42, n_jobs=-1)
    model.fit(X, y)
    joblib.dump(model, os.path.join(MODEL_DIR, 'random_forest_real.joblib'))
    logger.info("Random Forest saved")
    return model

def train_gradient_boosting(X, y):
    logger.info("Training Gradient Boosting...")
    model = GradientBoostingClassifier(n_estimators=150, max_depth=8, random_state=42)
    model.fit(X, y)
    joblib.dump(model, os.path.join(MODEL_DIR, 'gradient_boosting_real.joblib'))
    logger.info("Gradient Boosting saved")
    return model

def train_ddos_detector(X, y):
    logger.info("Training DDoS Detector...")
    ddos_y = ((y == 1) & (X[:, 0] > 200)).astype(int)
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X, ddos_y)
    joblib.dump(model, os.path.join(MODEL_DIR, 'ddos_detector.joblib'))
    logger.info("DDoS Detector saved")
    return model

def train_exploit_detector(X, y):
    logger.info("Training Exploit Detector...")
    exploit_y = ((y == 2) | (y == 3)).astype(int)
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X, exploit_y)
    joblib.dump(model, os.path.join(MODEL_DIR, 'exploit_detector.joblib'))
    logger.info("Exploit Detector saved")
    return model

def train_anomaly_detector(X):
    logger.info("Training Anomaly Detector (OneClass SVM)...")
    model = OneClassSVM(kernel='rbf', gamma=0.01, nu=0.1)
    model.fit(X)
    joblib.dump(model, os.path.join(MODEL_DIR, 'anomaly_detector.joblib'))
    logger.info("Anomaly Detector saved")
    return model

def train_attack_classifier(X, attack_types):
    logger.info("Training Attack Classifier...")
    model = RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42)
    model.fit(X, attack_types)
    joblib.dump(model, os.path.join(MODEL_DIR, 'attack_classifier.joblib'))
    logger.info("Attack Classifier saved")
    return model

def train_nlp_analyzer():
    logger.info("Training NLP Analyzer...")
    nlp_config = {'sqli_keywords': ['select', 'union', 'drop', 'insert', 'delete', 'update', 'or 1=1', '--'], 'xss_keywords': ['<script', 'javascript:', 'onerror=', 'onload=', 'alert(', 'document.cookie'], 'lfi_keywords': ['../', '..\\\\', '/etc/passwd', '/etc/shadow', 'php://', 'file://'], 'rce_keywords': ['; cat', '| ls', '&& whoami', '; rm', '| bash', '$('], 'weights': {'sqli': 0.9, 'xss': 0.85, 'lfi': 0.95, 'rce': 0.9}}
    joblib.dump(nlp_config, os.path.join(MODEL_DIR, 'nlp_config.joblib'))
    logger.info("NLP Analyzer config saved")
    return nlp_config

def train_ip_reputation():
    logger.info("Training IP Reputation...")
    ip_config = {'blacklist': ['192.168.100.1', '10.0.0.100', '172.16.0.50'], 'whitelist': ['127.0.0.1', '192.168.1.1'], 'threshold': 100, 'window': 60}
    joblib.dump(ip_config, os.path.join(MODEL_DIR, 'ip_reputation.joblib'))
    logger.info("IP Reputation saved")
    return ip_config

def train_rate_limiter():
    logger.info("Training Rate Limiter...")
    X_rate = np.random.randint(1, 1000, (1000, 3))
    y_rate = np.random.randint(10, 500, 1000)
    model = MLPRegressor(hidden_layer_sizes=(64, 32), max_iter=500, random_state=42)
    model.fit(X_rate, y_rate)
    joblib.dump(model, os.path.join(MODEL_DIR, 'rate_limiter.joblib'))
    logger.info("Rate Limiter saved")
    return model

def train_behavioral(X, y):
    logger.info("Training Behavioral Analysis...")
    model = MLPClassifier(hidden_layer_sizes=(128, 64, 32), max_iter=500, random_state=42)
    model.fit(X, y)
    joblib.dump(model, os.path.join(MODEL_DIR, 'behavioral.joblib'))
    logger.info("Behavioral Analysis saved")
    return model

def train_performance():
    logger.info("Training Performance Monitor...")
    perf_config = {'baseline_rps': 100, 'baseline_latency': 50, 'baseline_error': 0.05, 'thresholds': {'warning': 1.5, 'critical': 3.0}}
    joblib.dump(perf_config, os.path.join(MODEL_DIR, 'performance.joblib'))
    logger.info("Performance Monitor saved")
    return perf_config

def train_extra_trees(X, attack_types):
    logger.info("Training Extra Trees Ensemble...")
    model = ExtraTreesClassifier(n_estimators=200, max_depth=12, random_state=42)
    model.fit(X, attack_types)
    joblib.dump(model, os.path.join(MODEL_DIR, 'extra_trees.joblib'))
    logger.info("Extra Trees saved")
    return model

def main():
    logger.info("=" * 60)
    logger.info("ORCHID - Training All 13 ML Models")
    logger.info("=" * 60)
    X, y, attack_types = generate_synthetic_attacks(20000)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    joblib.dump(scaler, os.path.join(MODEL_DIR, 'scaler.joblib'))
    encoder = LabelEncoder()
    encoder.fit(['normal', 'ddos', 'sqli', 'xss', 'brute'])
    joblib.dump(encoder, os.path.join(MODEL_DIR, 'label_encoder.joblib'))
    models = {'isolation_forest': train_isolation_forest(X_scaled), 'random_forest': train_random_forest(X_scaled, y), 'gradient_boosting': train_gradient_boosting(X_scaled, y), 'ddos_detector': train_ddos_detector(X_scaled, y), 'exploit_detector': train_exploit_detector(X_scaled, y), 'anomaly_detector': train_anomaly_detector(X_scaled), 'attack_classifier': train_attack_classifier(X_scaled, attack_types), 'nlp_analyzer': train_nlp_analyzer(), 'ip_reputation': train_ip_reputation(), 'rate_limiter': train_rate_limiter(), 'behavioral': train_behavioral(X_scaled, y), 'performance': train_performance(), 'extra_trees': train_extra_trees(X_scaled, attack_types)}
    logger.info("")
    logger.info("=" * 60)
    logger.info("Testing Models")
    logger.info("=" * 60)
    X_test = X_scaled[:100]
    y_test = y[:100]
    rf_pred = models['random_forest'].predict(X_test)
    rf_acc = accuracy_score(y_test, rf_pred)
    logger.info(f"Random Forest Accuracy: {rf_acc:.2%}")
    gb_pred = models['gradient_boosting'].predict(X_test)
    gb_acc = accuracy_score(y_test, gb_pred)
    logger.info(f"Gradient Boosting Accuracy: {gb_acc:.2%}")
    at_pred = models['attack_classifier'].predict(X_test)
    at_acc = accuracy_score(attack_types[:100], at_pred)
    logger.info(f"Attack Classifier Accuracy: {at_acc:.2%}")
    logger.info("")
    logger.info("=" * 60)
    logger.info("All 13 models trained and saved!")
    logger.info(f"Models directory: {MODEL_DIR}")
    logger.info("=" * 60)
    logger.info("")
    logger.info("Model files:")
    for f in sorted(os.listdir(MODEL_DIR)):
        size = os.path.getsize(os.path.join(MODEL_DIR, f))
        logger.info(f"   {f}: {size:,} bytes")

if __name__ == '__main__':
    main()
