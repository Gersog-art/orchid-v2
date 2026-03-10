#!/usr/bin/env python3
"""
DDoS Detection ML Service
Анализирует трафик и определяет DDoS атаки
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import numpy as np
from datetime import datetime
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ddos_detector')

app = FastAPI(title="DDoS Detector ML")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Глобальное состояние для отслеживания трафика
class TrafficState:
    def __init__(self):
        self.ip_requests = defaultdict(list)  # IP -> [timestamps]
        self.ip_endpoints = defaultdict(set)  # IP -> {endpoints}
        self.ip_payloads = defaultdict(list)  # IP -> [payload_sizes]
        self.baseline_rps = 10  # Базовый RPS
        self.baseline_endpoints = 5  # Базовое количество endpoint'ов
        
state = TrafficState()

class TrafficRequest(BaseModel):
    ip: str
    endpoint: str
    payload_size: int = 0
    timestamp: float = None

class DetectionResult(BaseModel):
    is_ddos: bool
    confidence: float
    reason: str
    action: str
    risk_score: float

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "DDoS Detector"}

@app.post("/analyze", response_model=DetectionResult)
async def analyze_traffic(request: TrafficRequest):
    """Анализ трафика на DDoS"""
    now = request.timestamp or datetime.now().timestamp()
    ip = request.ip
    
    # Добавляем запрос в историю
    state.ip_requests[ip].append(now)
    state.ip_endpoints[ip].add(request.endpoint)
    state.ip_payloads[ip].append(request.payload_size)
    
    # Очищаем старые записи (последние 60 секунд)
    cutoff = now - 60
    state.ip_requests[ip] = [t for t in state.ip_requests[ip] if t > cutoff]
    
    # Считаем метрики
    rps = len(state.ip_requests[ip])
    unique_endpoints = len(state.ip_endpoints[ip])
    avg_payload = np.mean(state.ip_payloads[ip][-10:]) if state.ip_payloads[ip] else 0
    
    # Детекция аномалий
    risk_score = 0.0
    reasons = []
    
    # Проверка 1: Высокий RPS
    if rps > state.baseline_rps * 5:
        risk_score += 0.4
        reasons.append(f"High RPS: {rps} (baseline: {state.baseline_rps})")
    
    # Проверка 2: Много уникальных endpoint'ов
    if unique_endpoints > state.baseline_endpoints * 3:
        risk_score += 0.3
        reasons.append(f"Many endpoints: {unique_endpoints}")
    
    # Проверка 3: Большие payload'ы
    if avg_payload > 1000:
        risk_score += 0.2
        reasons.append(f"Large payloads: {avg_payload:.0f} bytes")
    
    # Проверка 4: Паттерн сканирования
    if unique_endpoints > 10 and rps > 20:
        risk_score += 0.3
        reasons.append("Scanning pattern detected")
    
    is_ddos = risk_score >= 0.5
    confidence = min(risk_score, 1.0)
    
    if is_ddos:
        action = "block"
        logger.warning(f"🚨 DDoS detected from {ip}: {reasons}")
    else:
        action = "allow"
    
    return DetectionResult(
        is_ddos=is_ddos,
        confidence=confidence,
        reason="; ".join(reasons) if reasons else "Normal traffic",
        action=action,
        risk_score=risk_score
    )

@app.get("/stats")
async def get_stats():
    """Статистика по трафику"""
    now = datetime.now().timestamp()
    cutoff = now - 60
    
    active_ips = sum(1 for ip, times in state.ip_requests.items() 
                     if any(t > cutoff for t in times))
    
    return {
        "active_ips": active_ips,
        "baseline_rps": state.baseline_rps,
        "baseline_endpoints": state.baseline_endpoints
    }

@app.post("/reset")
async def reset_stats():
    """Сброс статистики"""
    state.ip_requests.clear()
    state.ip_endpoints.clear()
    state.ip_payloads.clear()
    return {"status": "reset"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8005)
