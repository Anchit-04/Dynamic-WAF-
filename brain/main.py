import os
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import PreTrainedTokenizerFast, AutoModelForSequenceClassification
import torch
import logging

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("WAF-Brain")

app = FastAPI(title="WAF Transformer Brain")

# --- Absolute path fix to avoid working directory issues ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_NAME = os.path.join(BASE_DIR, "production_waf_brain")

logger.info(f"Initiating Brain Transplant using path: {MODEL_NAME}")
logger.info(f"Path exists: {os.path.exists(MODEL_NAME)}")
logger.info(f"Files found: {os.listdir(MODEL_NAME) if os.path.exists(MODEL_NAME) else 'FOLDER NOT FOUND'}")

try:
    # Load directly from tokenizer.json, bypassing sentencepiece/tiktoken requirement
    tokenizer = PreTrainedTokenizerFast(
        tokenizer_file=os.path.join(MODEL_NAME, "tokenizer.json")
    )

    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_NAME, 
        local_files_only=True
    )
    
    model.eval()
    logger.info("✅ Brain is online and ready for Layer 2 analysis.")

except Exception as e:
    logger.error(f"❌ Failed to load model: {e}")
    logger.info("CRITICAL: Make sure the 'production_waf_brain' folder exists next to main.py")
    raise e

# --- API Data Structures ---
class BrainRequest(BaseModel):
    payload: str

# --- Inference Route ---
@app.post("/analyze")
async def analyze_payload(request: BrainRequest):
    # Tokenize the incoming payload
    inputs = tokenizer(
        request.payload, 
        return_tensors="pt", 
        truncation=True, 
        max_length=512
    )
    
    # Run Inference
    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
    
    # malicious_score (Probability of class 1)
    malicious_score = probs[0][1].item()
    
    # Decision Logic
    decision = "block" if malicious_score > 0.85 else "pass"
    
    logger.info(f"Analyzed: '{request.payload[:30]}...' | Score: {malicious_score:.4f} | Action: {decision.upper()}")
    
    return {
        "score": malicious_score,
        "action": decision
    }

# --- Execution ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5000)