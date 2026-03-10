#!/usr/bin/env python3
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
import os
import logging

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
logger = logging.getLogger(__name__)

# Пути к моделям (абсолютные для Docker)
MODEL_DIR = os.environ.get('MODEL_PATH', '/app/models')
ISO_MODEL_PATH = os.path.join(MODEL_DIR, 'isolation_forest_real.joblib')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')

iso_model = None
scaler = None

class PredictionRequest(BaseModel):
    features: dict
    metadata: dict = {}

@app.get("/health")
async def health():
    if iso_model is not None and scaler is not None:
        return {"status": "healthy", "model_loaded": True}
    return {"status": "unhealthy", "model_loaded": False}

@app.on_event("startup")
async def load_models():
    global iso_model, scaler
    try:
        logger.info(f"Loading models from {MODEL_DIR}...")
        iso_model = joblib.load(ISO_MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        logger.info("✅ Models loaded successfully")
    except Exception as e:
        logger.error(f"❌ Error loading models: {e}")

@app.post("/predict")
async def predict(request: PredictionRequest):
    if iso_model is None or scaler is None:
        return {"error": "Model not loaded", "service": "Isolation Forest"}
    
    try:
        features = request.features
        X = np.array([[
            features.get('payload_length', 0),
            features.get('endpoint_length', 0),
            features.get('sql_keywords', 0),
            features.get('xss_patterns', 0),
            features.get('lfi_patterns', 0),
            features.get('special_chars', 0),
            features.get('digits', 0)
        ]])
        
        X_scaled = scaler.transform(X)
        prediction = iso_model.predict(X_scaled)[0]
        score = iso_model.score_samples(X_scaled)[0]
        
        result = "anomaly" if prediction == -1 else "normal"
        return {
            "result": result,
            "score": float(score),
            "service": "Isolation Forest",
            "model_used": True
        }
    except Exception as e:
        return {"error": str(e), "service": "Isolation Forest"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
