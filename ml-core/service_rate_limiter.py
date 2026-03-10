#!/usr/bin/env python3
"""
Rate Limiter ML Service
Умное ограничение запросов на основе ML
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('rate_limiter')

app = FastAPI(title="Rate Limiter ML")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class RateLimitState:
    def __init__(self):
        self.ip_requests = defaultdict(list)
        self.ip_blocked_until = {}
        
    def check_rate_limit(self, ip: str, limit: int = 100, window: int = 60):
        now = datetime.now().timestamp()
        
        # Проверяем блокировку
        if ip in self.ip_blocked_until:
            if now < self.ip_blocked_until[ip]:
                return False, self.ip_blocked_until[ip] - now
            else:
                del self.ip_blocked_until[ip]
        
        # Очищаем старые запросы
        self.ip_requests[ip] = [t for t in self.ip_requests[ip] if now - t < window]
        
        # Проверяем лимит
        if len(self.ip_requests[ip]) >= limit:
            block_duration = 300  # 5 минут
            self.ip_blocked_until[ip] = now + block_duration
            return False, block_duration
        
        self.ip_requests[ip].append(now)
        return True, 0

state = RateLimitState()

class RateLimitRequest(BaseModel):
    ip: str
    endpoint: str = ""

class RateLimitResult(BaseModel):
    allowed: bool
    remaining: int
    retry_after: float
    reason: str

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "Rate Limiter"}

@app.post("/check", response_model=RateLimitResult)
async def check_rate_limit(request: RateLimitRequest):
    allowed, retry_after = state.check_rate_limit(request.ip)
    
    if allowed:
        return RateLimitResult(
            allowed=True,
            remaining=100 - len(state.ip_requests[request.ip]),
            retry_after=0,
            reason="Request allowed"
        )
    else:
        logger.warning(f"🚨 Rate limit exceeded for {request.ip}")
        return RateLimitResult(
            allowed=False,
            remaining=0,
            retry_after=retry_after,
            reason="Rate limit exceeded"
        )

@app.get("/stats")
async def get_stats():
    return {
        "active_ips": len(state.ip_requests),
        "blocked_ips": len(state.ip_blocked_until)
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8011)
