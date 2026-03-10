#!/usr/bin/env python3
"""
Attack Classification Service
Использует готовую модель для классификации типов атак
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('attack_classifier')

app = FastAPI(title="Attack Classifier")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Готовые правила классификации на основе OWASP Top 10
ATTACK_SIGNATURES = {
    'SQL Injection': {
        'patterns': ['union select', "' or '1'='1", 'drop table', '1=1--', 'xp_cmdshell'],
        'severity': 'critical',
        'cwe': 'CWE-89'
    },
    'XSS': {
        'patterns': ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert('],
        'severity': 'high',
        'cwe': 'CWE-79'
    },
    'Path Traversal': {
        'patterns': ['../', '..\\', '%2e%2e', '/etc/passwd', '/etc/shadow'],
        'severity': 'high',
        'cwe': 'CWE-22'
    },
    'Command Injection': {
        'patterns': ['; cat ', '| ls ', '&& whoami', '$(id)', '`whoami`'],
        'severity': 'critical',
        'cwe': 'CWE-78'
    },
    'XXE': {
        'patterns': ['<!DOCTYPE', '<!ENTITY', 'SYSTEM "', 'PUBLIC "'],
        'severity': 'critical',
        'cwe': 'CWE-611'
    },
    'SSRF': {
        'patterns': ['169.254.169.254', 'localhost:', '127.0.0.1', '0.0.0.0'],
        'severity': 'high',
        'cwe': 'CWE-918'
    },
    'SSTI': {
        'patterns': ['{{', '}}', '${', '<%=', '<%'],
        'severity': 'high',
        'cwe': 'CWE-1336'
    },
    'NoSQL Injection': {
        'patterns': ['$ne', '$gt', '$lt', '$regex', '{$where}'],
        'severity': 'high',
        'cwe': 'CWE-943'
    },
    'LDAP Injection': {
        'patterns': [')(', '(|(', '(&(', '!(', '*\\)'],
        'severity': 'high',
        'cwe': 'CWE-90'
    },
    'RFI': {
        'patterns': ['=http://', '=https://', '.php?', '.asp?'],
        'severity': 'critical',
        'cwe': 'CWE-95'
    }
}

class AttackRequest(BaseModel):
    payload: str
    endpoint: str = ""
    method: str = "GET"
    headers: dict = {}

class ClassificationResult(BaseModel):
    attack_type: str
    confidence: float
    severity: str
    cwe: str
    patterns_matched: list
    recommendation: str

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "Attack Classifier"}

@app.post("/classify", response_model=ClassificationResult)
async def classify_attack(request: AttackRequest):
    """Классификация атаки"""
    payload_lower = request.payload.lower()
    
    best_match = None
    best_score = 0.0
    matched_patterns = []
    
    for attack_type, config in ATTACK_SIGNATURES.items():
        score = 0.0
        for pattern in config['patterns']:
            if pattern.lower() in payload_lower:
                score += 0.2
                matched_patterns.append(pattern)
        
        if score > best_score:
            best_score = score
            best_match = attack_type
    
    if best_match and best_score > 0.2:
        config = ATTACK_SIGNATURES[best_match]
        return ClassificationResult(
            attack_type=best_match,
            confidence=min(best_score, 1.0),
            severity=config['severity'],
            cwe=config['cwe'],
            patterns_matched=matched_patterns[:5],
            recommendation=f"Block request and log {config['cwe']} attack"
        )
    
    return ClassificationResult(
        attack_type="Unknown",
        confidence=0.0,
        severity="low",
        cwe="N/A",
        patterns_matched=[],
        recommendation="Allow request"
    )

@app.get("/signatures")
async def get_signatures():
    """Получить список сигнатур"""
    return {
        "attack_types": list(ATTACK_SIGNATURES.keys()),
        "total_signatures": sum(len(s['patterns']) for s in ATTACK_SIGNATURES.values())
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8008)
