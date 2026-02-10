from fastapi import APIRouter, HTTPException, status
from jwcrypto import jwk
from app.core.config import settings
import json

router = APIRouter()

@router.get("/jwks.json", response_model=dict)
def get_jwks():
    """
    Exposes the Public Key in JWK (JSON Web Key) format.
    Resource Servers use this to verify signatures without sharing secrets.
    """
    try:
        # Load the public key from settings (PEM format)
        key = jwk.JWK.from_pem(settings.PUBLIC_KEY.encode('utf-8'))
        raw_key = key.export_public()

        if isinstance(raw_key, dict):
            public_key_json = raw_key
        else:
            public_key_json = json.loads(str(raw_key))
        
        # Add required OIDC fields
        # 'kid': Key ID, must match the 'kid' in the JWT header
        # 'use': usage type, 'sig' stands for signature
        # 'alg': algorithm, usually RS256
        public_key_json["kid"] = settings.SIG_KEY_ID 
        public_key_json["use"] = "sig"
        public_key_json["alg"] = settings.ALGORITHM

        return {"keys": [public_key_json]}
        
    except Exception as e:
        # Log the specific error in production
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail="Failed to generate JWKS"
        )

@router.get("/openid-configuration", response_model=dict)
def get_openid_configuration():
    """
    Standard OIDC Discovery Endpoint.
    Clients use this to automatically discover endpoints and capabilities.
    """
    # Ideally, SERVER_HOST should be defined in settings (e.g., https://id.example.com)
    # Fallback to localhost for local development
    server_host = getattr(settings, "SERVER_HOST", "http://localhost:8000")
    base_url = f"{server_host}{settings.API_V1_STR}"
    
    return {
        "issuer": server_host,
        "token_endpoint": f"{base_url}/auth/login",
        "userinfo_endpoint": f"{base_url}/users/me",
        "jwks_uri": f"{server_host}/.well-known/jwks.json",
        "response_types_supported": ["token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [settings.ALGORITHM],
        "scopes_supported": ["openid", "email", "profile"]
    }