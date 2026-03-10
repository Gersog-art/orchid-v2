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

MODEL_DIR = os.environ.get('MODEL_PATH', '/app/models')
RF_MODEL_PATH = os.path.join(MODEL_DIR, 'random_forest_real.joblib')
GB_MODEL_PATH = os.path.join(MODEL_DIR, 'gradient_boosting_real.joblib')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.joblib')
ENCODER_PATH = os.path.join(MODEL_DIR, 'label_encoder.joblib')

rf_model = None
gb_model = None
scaler = None
encoder = None

class PredictionRequest(BaseModel):
    features: dict
    metadata: dict = {}

@app.get("/health")
async def health():
    if rf_model is not None and encoder is not None:
        return {"status": "healthy", "model_loaded": True}
    return {"status": "unhealthy", "model_loaded": False}

@app.on_event("startup")
async def load_models():
    global rf_model, gb_model, scaler, encoder
    try:
        logger.info(f"Loading models from {MODEL_DIR}...")
        rf_model = joblib.load(RF_MODEL_PATH)
        gb_model = joblib.load(GB_MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        encoder = joblib.load(ENCODER_PATH)
        logger.info("✅ Models loaded successfully")
    except Exception as e:
        logger.error(f"❌ Error loading models: {e}")

@app.post("/predict")
async def predict(request: PredictionRequest):
    if rf_model is None or encoder is None:
        return {"error": "Model not loaded", "service": "Random Forest"}
    
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
        
        # Random Forest prediction
        rf_pred = rf_model.predict(X_scaled)[0]
        rf_confidence = float(np.max(rf_model.predict_proba(X_scaled)[0]))
        rf_type = encoder.inverse_transform([rf_pred])[0]
        
        # Gradient Boosting prediction
        gb_pred = gb_model.predict(X_scaled)[0]
        gb_type = encoder.inverse_transform([gb_pred])[0]
        
        return {
            "attack_type": rf_type,
            "confidence": rf_confidence,
            "rf_prediction": rf_type,
            "gb_prediction": gb_type,
            "service": "Random Forest + Gradient Boosting Ensemble",
            "model_used": True
        }
    except Exception as e:
        return {"error": str(e), "service": "Random Forest"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
