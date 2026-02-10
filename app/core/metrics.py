from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Gauge, Histogram
from fastapi import FastAPI, Request
from sqlalchemy.pool import QueuePool

from app.core.db import engine


# Business & Security Metrics
AUTH_EVENTS = Counter(
    "identity_auth_events_total",
    "Total count of authentication attempts",
    ["method", "status"]
)

# Infrastructure Metrics
DB_POOL_CHECKED_OUT = Gauge(
    "identity_db_pool_checked_out",
    "Current number of active database connections"
)

DB_POOL_OVERFLOW = Gauge(
    "identity_db_pool_overflow",
    "Current number of overflow database connections"
)

# Latency Metrics
CRYPTO_OP_DURATION = Histogram(
    "identity_crypto_op_duration_seconds",
    "Time spent on cryptographic operations like Argon2",
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
)


def update_db_pool_metrics() -> None:
    """Update database pool metrics if using QueuePool"""
    pool = engine.pool
    
    if isinstance(pool, QueuePool):
        DB_POOL_CHECKED_OUT.set(pool.checkedout())
        DB_POOL_OVERFLOW.set(pool.overflow())


def setup_metrics(app: FastAPI) -> None:
    """
    Initialize Prometheus instrumentator and register custom metrics.
    Exposes metrics endpoint at /metrics
    """
    instrumentator = Instrumentator(
        should_group_status_codes=True,
    )

    instrumentator.instrument(app).expose(app, endpoint="/metrics")

    # Add middleware to update DB pool metrics on each request
    @app.middleware("http")
    async def metrics_middleware(request: Request, call_next):
        update_db_pool_metrics()
        response = await call_next(request)
        return response