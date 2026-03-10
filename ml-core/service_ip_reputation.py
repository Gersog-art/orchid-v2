#!/usr/bin/env python3
"""
IP Reputation Service
Проверка IP на основе чёрных списков и геолокации
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('ip_reputation')

app = FastAPI(title="IP Reputation Service")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Простые чёрные списки (можно расширить)
PRIVATE_RANGES = [
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('127.0.0.0', '127.255.255.255'),
]

class IPRequest(BaseModel):
    ip: str
    request_count: int = 1
    time_window: int = 60

class IPResult(BaseModel):
    ip: str
    is_private: bool
    risk_score: float
    reputation: str
    recommendation: str
    details: dict

def ip_to_int(ip):
    """Конвертация IP в integer"""
    try:
        parts = ip.split('.')
        return (int(parts[0]) << 24) + (int(parts[1]) << 16) + (int(parts[2]) << 8) + int(parts[3])
    except:
        return 0

def is_private_ip(ip):
    """Проверка на приватный IP"""
    ip_int = ip_to_int(ip)
    for start, end in PRIVATE_RANGES:
        if ip_to_int(start) <= ip_int <= ip_to_int(end):
            return True
    return False

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "IP Reputation"}

@app.post("/check", response_model=IPResult)
async def check_ip(request: IPRequest):
    """Проверка IP репутации"""
    is_private = is_private_ip(request.ip)
    
    # Считаем risk score
    risk_score = 0.0
    details = {}
    
    # Приватные IP - меньший риск
    if is_private:
        risk_score += 0.1
        details['network_type'] = 'private'
    else:
        details['network_type'] = 'public'
    
    # Высокий RPS увеличивает риск
    rps = request.request_count / max(request.time_window, 1)
    if rps > 100:
        risk_score += 0.5
        details['rps'] = f'{rps:.1f} (very high)'
    elif rps > 50:
        risk_score += 0.3
        details['rps'] = f'{rps:.1f} (high)'
    elif rps > 10:
        risk_score += 0.1
        details['rps'] = f'{rps:.1f} (normal)'
    else:
        details['rps'] = f'{rps:.1f} (low)'
    
    # Определяем репутацию
    if risk_score >= 0.7:
        reputation = 'malicious'
        recommendation = 'block'
    elif risk_score >= 0.4:
        reputation = 'suspicious'
        recommendation = 'monitor'
    else:
        reputation = 'clean'
        recommendation = 'allow'
    
    if reputation != 'clean':
        logger.warning(f"⚠️ Suspicious IP: {request.ip} (risk: {risk_score:.2f})")
    
    return IPResult(
        ip=request.ip,
        is_private=is_private,
        risk_score=min(risk_score, 1.0),
        reputation=reputation,
        recommendation=recommendation,
        details=details
    )

@app.get("/stats")
async def get_stats():
    """Статистика"""
    return {
        "service": "IP Reputation",
        "features": ["private_ip_detection", "rps_analysis", "risk_scoring"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8010)
