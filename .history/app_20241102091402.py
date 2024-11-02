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

# Load BIP39 wordlist
try:
    with open("english.txt", "r") as bip39_wordlist_file:
        WORD_LIST = bip39_wordlist_file.read().splitlines()
    if len(WORD_LIST) != 2048:  # BIP39 requires exactly 2048 words
        raise ValueError("Invalid BIP39 wordlist length")
except FileNotFoundError:
    raise Exception("BIP39 wordlist file not found. Ensure 'english.txt' is present.")
except Exception as e:
    raise Exception(f"Failed to load BIP39 wordlist: {str(e)}")

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
        
        # Convert key bytes to binary string
        bits = ''.join(format(byte, '08b') for byte in key_bytes)
        
        # Calculate checksum
        checksum_length = len(bits) // 32  # 1 bit of checksum for every 32 bits of key
        checksum = sha256(key_bytes).digest()
        checksum_bits = ''.join(format(byte, '08b') for byte in checksum)[:checksum_length]
        
        # Combine key bits with checksum
        total_bits = bits + checksum_bits
        
        # Split into 11-bit segments (since 2048 = 2^11)
        segments = [total_bits[i:i+11] for i in range(0, len(total_bits), 11)]
        
        # Convert each 11-bit segment to a word
        words = []
        for segment in segments:
            index = int(segment, 2)
            if index >= len(WORD_LIST):
                raise ValueError(f"Invalid word index: {index}")
            words.append(WORD_LIST[index])
        
        return ' '.join(words)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid base64 key: {str(e)}")

def mnemonic_to_base64(mnemonic: str) -> str:
    try:
        words = mnemonic.lower().strip().split()
        
        # Convert words to binary
        bits = ''
        for word in words:
            if word not in WORD_LIST:
                raise ValueError(f"Invalid word in mnemonic: {word}")
            index = WORD_LIST.index(word)
            bits += format(index, '011b')  # 11 bits per word
        
        # Separate checksum from key bits
        checksum_length = len(bits) // 33  # 1 bit of checksum for every 32 bits of key
        key_bits = bits[:-checksum_length]
        checksum_bits = bits[-checksum_length:]
        
        # Convert key bits to bytes
        key_bytes = bytearray()
        for i in range(0, len(key_bits), 8):
            byte_bits = key_bits[i:i+8]
            if len(byte_bits) == 8:
                key_bytes.append(int(byte_bits, 2))
        
        # Verify checksum
        calculated_checksum = sha256(key_bytes).digest()
        calculated_checksum_bits = ''.join(format(byte, '08b') for byte in calculated_checksum)[:checksum_length]
        if calculated_checksum_bits != checksum_bits:
            raise ValueError("Invalid checksum")
        
        # Convert to base64
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
            "valid": mnemonic.lower().strip() == regenerated_mnemonic.lower(),
            "regenerated_mnemonic": regenerated_mnemonic
        }
    except Exception as e:
        return {
            "valid": False, 
            "regenerated_mnemonic": None,
            "error": str(e)
        }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")