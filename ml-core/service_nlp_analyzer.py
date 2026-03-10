#!/usr/bin/env python3
"""
NLP Payload Analyzer
Использует NLP для анализа вредоносных payload'ов
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re
import logging
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('nlp_analyzer')

app = FastAPI(title="NLP Payload Analyzer")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Токенизация и анализ
class NLPRequest(BaseModel):
    payload: str
    url: str = ""
    user_agent: str = ""

class NLPResult(BaseModel):
    is_malicious: bool
    confidence: float
    tokens: list
    suspicious_keywords: list
    encoding_detected: str
    threat_score: float

def tokenize(text):
    """Токенизация текста"""
    # Удаляем специальные символы
    text = re.sub(r'[^\w\s]', ' ', text)
    return text.lower().split()

def _analyze_payload_local(payload):
    """NLP анализ payload"""
    suspicious_keywords = [
        'select', 'union', 'drop', 'insert', 'delete', 'update',
        'script', 'alert', 'eval', 'exec', 'system',
        'passwd', 'shadow', 'admin', 'root', 'password',
        'http', 'https', 'ftp', 'file', 'data',
        'union', 'select', 'from', 'where', 'order', 'group'
    ]
    
    tokens = tokenize(payload)
    token_counts = Counter(tokens)
    
    # Находим подозрительные ключевые слова
    found_suspicious = []
    for keyword in suspicious_keywords:
        if keyword in tokens:
            found_suspicious.append(keyword)
    
    # Определяем encoding
    encoding = 'plain'
    if '%' in payload:
        encoding = 'url-encoded'
    elif '&#' in payload:
        encoding = 'html-encoded'
    elif '\\' in payload:
        encoding = 'escaped'
    
    # Считаем threat score
    threat_score = 0.0
    threat_score += min(len(found_suspicious) * 0.15, 0.6)
    threat_score += 0.2 if encoding != 'plain' else 0
    threat_score += 0.2 if len(payload) > 500 else 0
    
    is_malicious = threat_score >= 0.4
    
    return {
        'is_malicious': is_malicious,
        'confidence': min(threat_score, 1.0),
        'tokens': tokens[:20],  # Первые 20 токенов
        'suspicious_keywords': found_suspicious,
        'encoding_detected': encoding,
        'threat_score': threat_score
    }

@app.get("/health")
async def health():
    return {"status": "healthy", "service": "NLP Analyzer"}

@app.post("/analyze", response_model=NLPResult)
async def analyze_payload(request: NLPRequest):
    """NLP анализ payload"""
    result = _analyze_payload_local(request.payload)
    
    if result['is_malicious']:
        logger.warning(f"🚨 Malicious payload detected: {result['suspicious_keywords']}")
    
    return NLPResult(**result)

@app.get("/stats")
async def get_stats():
    """Статистика"""
    return {
        "service": "NLP Analyzer",
        "features": ["tokenization", "keyword_detection", "encoding_detection"]
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8009)
