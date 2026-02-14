import secrets
import hashlib
import base64
import httpx
from fastapi import HTTPException, status, Request
from app.core.config import settings
from app.core.logging import logger
from app.schemas.auth import GoogleUserInfo
from app.core.metrics import AUTH_EVENTS

class GoogleService:
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo"

    @staticmethod
    def generate_pkce_pair():
        """Generate PKCE code verifier and challenge."""
        code_verifier = secrets.token_urlsafe(64)
        hashed = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(hashed).decode("ascii").rstrip("=")
        return code_verifier, code_challenge

    @staticmethod
    def generate_login_url():
        """Construct the Google Login URL."""
        if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI:
            raise HTTPException(status_code=500, detail="Google OAuth not configured")

        state = secrets.token_urlsafe(32)
        code_verifier, code_challenge = GoogleService.generate_pkce_pair()

        auth_url = (
            "https://accounts.google.com/o/oauth2/auth"
            "?response_type=code"
            f"&client_id={settings.GOOGLE_CLIENT_ID}"
            f"&redirect_uri={settings.GOOGLE_REDIRECT_URI}"
            "&scope=openid%20email%20profile"
            "&access_type=offline"
            f"&state={state}"
            f"&code_challenge={code_challenge}"
            "&code_challenge_method=S256"
        )
        return auth_url, state, code_verifier

    @classmethod
    async def get_user_from_callback(cls, request: Request) -> GoogleUserInfo:
        """
        Handle the full OAuth2 callback flow: 
        Validation -> Token Exchange -> Fetch User Info.
        """
        # Extract & Validate Params
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
            logger.error("google_oauth_callback_error", error=error)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Google Error: {error}")

        if not code or not state:
            AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
            logger.warning("google_oauth_missing_params")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state")

        # Validate Cookies (CSRF & PKCE)
        cookie_state = request.cookies.get("oauth_state")
        code_verifier = request.cookies.get("oauth_verifier")

        if not cookie_state or state != cookie_state:
            AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
            logger.error("google_oauth_csrf_detected", state=state, cookie_state=cookie_state)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="CSRF validation failed")

        if not code_verifier:
            AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
            logger.error("google_oauth_missing_verifier")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="PKCE verifier not found")

        # Exchange Code for Token
        logger.info("google_oauth_exchanging_code")
        async with httpx.AsyncClient() as client:
            token_payload = {
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": code_verifier,
            }
            
            token_res = await client.post(cls.TOKEN_URL, data=token_payload)
            if token_res.status_code != 200:
                AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
                logger.error("google_token_exchange_failed", response=token_res.text)
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to get tokens")

            access_token = token_res.json().get("access_token")

            # Fetch User Profile
            user_info_res = await client.get(
                cls.USER_INFO_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if user_info_res.status_code != 200:
                AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
                logger.error("google_user_info_fetch_failed", response=user_info_res.text)
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Failed to get user info")

            try:
                return GoogleUserInfo(**user_info_res.json())
            except Exception as e:
                AUTH_EVENTS.labels(method="google_login", status="error_callback").inc()
                logger.error("google_user_data_parsing_failed", error=str(e))
                raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid user data format")