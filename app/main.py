from typing import cast
from fastapi import FastAPI, Request, Response
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from app.core.limiter import limiter
from app.core.config import settings
from app.api.v1.endpoints import users
from app.api.v1.endpoints import auth
from app.api.v1.endpoints import health
from app.core.logging import setup_logging
from app.core.metrics import setup_metrics
from app.middleware.log_middleware import LoggingMiddleware
from app.api.v1.endpoints import well_known


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Initialize logging
    setup_logging()
    yield
    # Shutdown: Add cleanup logic here if needed


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)


# Middleware registration order matters - from outer to inner:
# CORS (outermost layer)
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Logging middleware
app.add_middleware(LoggingMiddleware)

# Rate limiter configuration
app.state.limiter = limiter

def rate_limit_handler(request: Request, exc: Exception) -> Response:
    return _rate_limit_exceeded_handler(request, cast(RateLimitExceeded, exc))

app.add_exception_handler(RateLimitExceeded, rate_limit_handler)

setup_metrics(app)

app.include_router(health.router, prefix=settings.API_V1_STR, tags=["health"])
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(users.router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(well_known.router, prefix="/.well-known", tags=["Discovery"])

@app.get("/")
async def root():
    """Root endpoint returning welcome message"""
    return {"message": f"Welcome to {settings.PROJECT_NAME}"}