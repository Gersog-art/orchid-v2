#!/usr/bin/env python3
"""
Anomaly Detection ML Service
Использует Isolation Forest для обнаружения аномалий
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
from sklearn.ensemble import IsolationForest
from datetime import datetime
import logging
import pickle
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('anomaly_detector')

app = FastAPI(title="Anomaly Detector ML")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Простая модель Isolation Forest
class SimpleAnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.is_fitted = False
        self.baseline_data = []
        
    def fit_baseline(self, data):
        """Обучение на базовых данных"""
        self.baseline_data = data
        if len(data) > 10:
            self.model.fit(np.array(data))
            self.is_fitted = True
            logger.info(f"✅ Model fitted on {len(data)} samples")
        
    def predict(self, features):
        """Предсказание аномалии"""
        if not self.is_fitted:
            # Если модель не обучена, используем простые эвристики
            return self._heuristic_predict(features)
        
        prediction = self.model.predict([features])[0]
        score = self.model.score_samples([features])[0]
        
        return prediction == -1, score
    
    def _heuristic_predict(self, features):
        """Эвристическое предсказание"""
        # features: [rps, payload_size, endpoint_count, request_size]
        score = 0.0
        
        if features[0] > 50:  # High RPS
            score += 0.4
        if features[1] > 1000:  # Large payload
            score += 0.3
        if features[2] > 20:  # Many endpoints
            score += 0.3
        
        is_anomaly = score >= 0.5
        return is_anomaly, 1.0 - score

detector = SimpleAnomalyDetector()

class AnomalyRequest(BaseModel):
    ip: str
    rps: float
    payload_size: int
    endpoint_count: int
    request_size: int = 0

class AnomalyResult(BaseModel):
    is_anomaly: bool
    confidence: float
    score: float
    action: str
    reason: str

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "Anomaly Detector",
        "model_fitted": detector.is_fitted
    }

@app.post("/analyze", response_model=AnomalyResult)
async def analyze_request(request: AnomalyRequest):
    """Анализ запроса на аномалии"""
    features = [
        request.rps,
        request.payload_size,
        request.endpoint_count,
        request.request_size
    ]
    
    is_anomaly, score = detector.predict(features)
    confidence = abs(score)
    
    reasons = []
    if request.rps > 50:
        reasons.append(f"High RPS: {request.rps}")
    if request.payload_size > 1000:
        reasons.append(f"Large payload: {request.payload_size}")
    if request.endpoint_count > 20:
        reasons.append(f"Many endpoints: {request.endpoint_count}")
    
    if is_anomaly:
        action = "block"
        reason = "; ".join(reasons) if reasons else "Anomaly detected"
        logger.warning(f"🚨 Anomaly detected from {request.ip}: {reason}")
    else:
        action = "allow"
        reason = "Normal traffic"
    
    return AnomalyResult(
        is_anomaly=is_anomaly,
        confidence=confidence,
        score=score,
        action=action,
        reason=reason
    )

@app.post("/train")
async def train_model(samples: list):
    """Обучение модели на новых данных"""
    if len(samples) > 10:
        detector.fit_baseline(samples)
        return {"status": "trained", "samples": len(samples)}
    return {"status": "insufficient_data", "samples": len(samples)}

@app.get("/stats")
async def get_stats():
    """Статистика модели"""
    return {
        "model_fitted": detector.is_fitted,
        "baseline_samples": len(detector.baseline_data)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8007)
