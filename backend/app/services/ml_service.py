import json
import logging
import os
import joblib
import numpy as np

from app.core.config import settings
from app.utils.url import validate_url_syntax

logger = logging.getLogger("aegis")

_model_artifact = None
_metadata = None


def load_model():
    """Loads the trained model artifact and metadata into memory."""
    global _model_artifact, _metadata

    if _model_artifact is not None:
        return _model_artifact

    model_path = settings.ML_MODEL_PATH
    if not os.path.isabs(model_path):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        model_path = os.path.join(base_dir, model_path)

    if not os.path.exists(model_path):
        logger.warning(f"ML model file not found at: {model_path}")
        return None

    try:
        _model_artifact = joblib.load(model_path)
        metadata_path = os.path.join(os.path.dirname(model_path), "model_metadata.json")
        if os.path.exists(metadata_path):
            with open(metadata_path, "r", encoding="utf-8") as f:
                _metadata = json.load(f)
        logger.info(f"Loaded ML model successfully from {model_path}")
        return _model_artifact
    except Exception as exc:
        logger.error(f"Failed to load ML model from {model_path}: {exc}")
        return None


def predict_url(url: str) -> dict:
    """
    Executes ML inference on a single URL using URLFeatureExtractor and the trained Random Forest model.
    Validates input URL syntax before inference to prevent invalid inputs from reaching feature extraction.
    Returns structured prediction, calibrated probability, and model metadata.
    """
    is_valid, validation_err = validate_url_syntax(url)
    if not is_valid:
        logger.warning(f"ML inference rejected invalid URL input: {validation_err}")
        return {
            "status": "invalid_input",
            "reason": f"Input validation error: {validation_err}"
        }

    try:
        artifact = load_model()
        if artifact is None:
            return {
                "status": "unavailable",
                "reason": "ML model file not found or failed to load"
            }


        model = artifact.get("model")
        extractor = artifact.get("extractor")

        if model is None or extractor is None:
            return {
                "status": "failed",
                "reason": "Model artifact corrupted or missing extractor"
            }

        # Extract features matching the exact training pipeline
        features = extractor.extract_vector(url)
        X = np.array([features])

        # Prediction and probabilities
        pred_label = int(model.predict(X)[0])
        probabilities = model.predict_proba(X)[0]

        # Label 1 is phishing, label 0 is legitimate
        phishing_prob = float(probabilities[1]) if len(probabilities) > 1 else float(pred_label)
        prediction_str = "phishing" if pred_label == 1 else "legitimate"
        confidence = round(phishing_prob if pred_label == 1 else (1.0 - phishing_prob), 4)

        return {
            "status": "completed",
            "prediction": prediction_str,
            "confidence": confidence,
            "phishing_probability": round(phishing_prob, 4),
            "model_name": (_metadata or {}).get("model_name", "PhishOFE-URL-Classifier"),
            "model_version": (_metadata or {}).get("version", "1.0"),
            "features_used": len(features)
        }

    except Exception as exc:
        logger.exception(f"ML prediction error for URL: {exc}")
        return {
            "status": "failed",
            "reason": str(exc)
        }