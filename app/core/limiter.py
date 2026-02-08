from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import settings

# Initialize Limiter with Redis storage
# key_func=get_remote_address: Identify users by their IP address
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=f"redis://{settings.REDIS_HOST}:6379/0",
    strategy="fixed-window",
)