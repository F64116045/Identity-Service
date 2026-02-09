from typing import cast
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import Counter, Gauge, Histogram
from fastapi import FastAPI
from sqlalchemy.pool import QueuePool
from app.core.db import engine

# --- Business & Security Metrics ---
AUTH_EVENTS = Counter(
    "identity_auth_events_total",
    "Total count of authentication attempts",
    ["method", "status"]
)

# --- Infrastructure Metrics ---
DB_POOL_CHECKED_OUT = Gauge(
    "identity_db_pool_checked_out",
    "Current number of active database connections"
)

DB_POOL_OVERFLOW = Gauge(
    "identity_db_pool_overflow",
    "Current number of overflow database connections"
)

# --- Latency Metrics ---
CRYPTO_OP_DURATION = Histogram(
    "identity_crypto_op_seconds",
    "Time spent on cryptographic operations like Argon2",
    buckets=[0.1, 0.5, 1.0, 2.0, 5.0]
)

def setup_metrics(app: FastAPI) -> None:
    """
    Initialize Prometheus instrumentator and register custom metrics.
    """
    instrumentator = Instrumentator(
        should_group_status_codes=True,
        should_ignore_untemplated=True,
        excluded_handlers=["/metrics", "/health"]
    )

    def update_pool_status() -> None:
        pool = cast(QueuePool, engine.pool)
        
        if hasattr(pool, "checkedout"):
            DB_POOL_CHECKED_OUT.set(pool.checkedout())
        
        if hasattr(pool, "overflow"):
            DB_POOL_OVERFLOW.set(pool.overflow())


    instrumentator.add(lambda _: update_pool_status())

    instrumentator.instrument(app).expose(app, endpoint="/metrics")