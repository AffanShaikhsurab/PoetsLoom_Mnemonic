from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from hashlib import sha256
import base64
import secrets
import json

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Word list for creating memorable phrases (you can expand this)
WORD_LIST = [
    "apple", "banana", "beach", "bird", "blue", "book", "brave", "bread",
    "calm", "chair", "clock", "cloud", "dance", "dark", "desk", "door",
    "earth", "east", "easy", "echo", "field", "fire", "fish", "flag",
    "gate", "gold", "grass", "green", "happy", "heart", "hill", "home",
    "ice", "iron", "jazz", "jump", "king", "lake", "lamp", "leaf",
    "light", "lion", "love", "luna", "magic", "moon", "music", "nest",
    "north", "ocean", "paint", "peace", "queen", "quick", "rain", "river",
    "road", "rock", "rose", "ruby", "sand", "seed", "ship", "star"
]

class KeyRequest(BaseModel):
    key: str

class MnemonicRequest(BaseModel):
    mnemonic: str

class KeyResponse(BaseModel):
    key: str
    mnemonic: str

class EncryptionResponse(BaseModel):
    key: str
    mnemonic: str
    iv: str

def base64_to_mnemonic(base64_key: str) -> str:
    try:
        # Decode base64 to bytes
        key_bytes = base64.b64decode(base64_key)
        
        # Create checksum using SHA256
        checksum = sha256(key_bytes).digest()[0]
        
        # Convert bytes to list of words
        words = []
        for i in range(0, len(key_bytes), 2):
            # Use pairs of bytes to select words
            if i < len(key_bytes) - 1:
                index = ((key_bytes[i] << 8) | key_bytes[i + 1]) % len(WORD_LIST)
            else:
                index = key_bytes[i] % len(WORD_LIST)
            words.append(WORD_LIST[index])
        
        # Add checksum word
        words.append(WORD_LIST[checksum % len(WORD_LIST)])
        
        return ' '.join(words)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 key: {str(e)}")

def mnemonic_to_base64(mnemonic: str) -> str:
    try:
        words = mnemonic.lower().split()
        if len(words) < 2:
            raise ValueError("Mnemonic too short")
        
        # Remove checksum word
        words = words[:-1]
        
        # Convert words back to bytes
        key_bytes = bytearray()
        for word in words:
            if word not in WORD_LIST:
                raise ValueError(f"Invalid word in mnemonic: {word}")
            index = WORD_LIST.index(word)
            key_bytes.extend([index >> 8, index & 0xFF])
        
        # Convert back to base64
        return base64.b64encode(bytes(key_bytes)).decode('utf-8')
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid mnemonic: {str(e)}")

@app.post("/generate_key", response_model=EncryptionResponse)
async def generate_key():
    """Generate a new random encryption key with IV"""
    try:
        # Generate 32-byte key for AES-256
        key_bytes = secrets.token_bytes(32)
        iv_bytes = secrets.token_bytes(16)
        
        key_base64 = base64.b64encode(key_bytes).decode('utf-8')
        iv_base64 = base64.b64encode(iv_bytes).decode('utf-8')
        
        mnemonic = base64_to_mnemonic(key_base64)
        
        return EncryptionResponse(
            key=key_base64,
            mnemonic=mnemonic,
            iv=iv_base64
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")

@app.post("/key_to_mnemonic", response_model=KeyResponse)
async def key_to_mnemonic(request: KeyRequest):
    """Convert a base64 key to mnemonic phrase"""
    try:
        mnemonic = base64_to_mnemonic(request.key)
        return KeyResponse(key=request.key, mnemonic=mnemonic)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Conversion failed: {str(e)}")

@app.post("/mnemonic_to_key", response_model=KeyResponse)
async def mnemonic_to_key(request: MnemonicRequest):
    """Convert a mnemonic phrase back to base64 key"""
    try:
        key = mnemonic_to_base64(request.mnemonic)
        return KeyResponse(key=key, mnemonic=request.mnemonic)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Conversion failed: {str(e)}")

@app.get("/verify_mnemonic/{mnemonic}")
async def verify_mnemonic(mnemonic: str):
    """Verify if a mnemonic phrase is valid"""
    try:
        # Convert to key and back to verify
        key = mnemonic_to_base64(mnemonic)
        regenerated_mnemonic = base64_to_mnemonic(key)
        
        return {
            "valid": mnemonic.lower() == regenerated_mnemonic.lower(),
            "regenerated_mnemonic": regenerated_mnemonic
        }
    except Exception:
        return {"valid": False, "regenerated_mnemonic": None}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")