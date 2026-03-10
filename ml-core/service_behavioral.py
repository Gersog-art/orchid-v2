#!/usr/bin/env python3
"""
Behavioral Analysis ML Service
Анализ поведения пользователей
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('behavioral')

app = FastAPI(title="Behavioral Analysis ML")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class BehavioralState:
    def __init__(self):
        self.user_profiles = defaultdict(lambda: {
            'avg_requests_per_minute': 10,
            'common_endpoints': set(),
            'common_methods': defaultdict(int),
            'last_seen': None
        })
        
    def analyze(self, ip: str, endpoint: str, method: str):
        profile = self.user_profiles[ip]
        now = datetime.now()
        
        # Обновляем профиль
        if profile['last_seen']:
            time_diff = (now - profile['last_seen']).total_seconds()
            if time_diff > 0:
                profile['avg_requests_per_minute'] = 60 / time_diff
        
        profile['common_endpoints'].add(endpoint)
        profile['common_methods'][method] += 1
        profile['last_seen'] = now
        
        # Анализируем аномалии
        risk_score = 0.0
        
        if profile['avg_requests_per_minute'] > 100:
            risk_score += 0.4
        if len(profile['common_endpoints']) > 50:
            risk_score += 0.3
        if profile['common_methods'].get('POST', 0) > 100:
            risk_score += 0.3
        
        return risk_score

state = BehavioralState()

class BehavioralRequest(BaseModel):
    ip: str
    endpoint: str
    method: str = "GET"

class BehavioralResult(BaseModel):
    risk_score: float
    behavior_type: str
    recommendation: str

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "Behavioral Analysis"}

@app.post("/analyze", response_model=BehavioralResult)
async def analyze_behavior(request: BehavioralRequest):
    risk_score = state.analyze(request.ip, request.endpoint, request.method)
    
    if risk_score >= 0.7:
        behavior_type = "malicious"
        recommendation = "block"
    elif risk_score >= 0.4:
        behavior_type = "suspicious"
        recommendation = "monitor"
    else:
        behavior_type = "normal"
        recommendation = "allow"
    
    return BehavioralResult(
        risk_score=risk_score,
        behavior_type=behavior_type,
        recommendation=recommendation
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8012)
