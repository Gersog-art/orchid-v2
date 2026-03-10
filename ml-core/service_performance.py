#!/usr/bin/env python3
"""
Performance Monitor ML Service
Мониторинг производительности системы
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
import time
import psutil

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('performance')

app = FastAPI(title="Performance Monitor ML")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PerformanceMetrics:
    def __init__(self):
        self.start_time = time.time()
        self.request_count = 0
        self.response_times = []
        
    def record_request(self, response_time: float):
        self.request_count += 1
        self.response_times.append(response_time)
        if len(self.response_times) > 1000:
            self.response_times = self.response_times[-1000:]
    
    def get_stats(self):
        uptime = time.time() - self.start_time
        avg_response = sum(self.response_times) / len(self.response_times) if self.response_times else 0
        
        return {
            "uptime_seconds": uptime,
            "total_requests": self.request_count,
            "avg_response_time_ms": avg_response * 1000,
            "requests_per_second": self.request_count / uptime if uptime > 0 else 0,
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent
        }

metrics = PerformanceMetrics()

class PerformanceRequest(BaseModel):
    response_time: float = 0.0

class PerformanceResult(BaseModel):
    status: str
    health_score: float
    metrics: dict

@app.get("/health")
async def health():
    stats = metrics.get_stats()
    health_score = 1.0
    
    if stats['cpu_percent'] > 80:
        health_score -= 0.3
    if stats['memory_percent'] > 80:
        health_score -= 0.3
    if stats['avg_response_time_ms'] > 1000:
        health_score -= 0.4
    
    status = "healthy" if health_score >= 0.7 else "degraded" if health_score >= 0.4 else "critical"
    
    return {
        "status": "healthy",
        "service": "Performance Monitor",
        "health_score": health_score,
        "system_status": status
    }

@app.post("/record")
async def record_request(request: PerformanceRequest):
    metrics.record_request(request.response_time)
    return {"recorded": True}

@app.get("/stats")
async def get_stats():
    return metrics.get_stats()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8013)
