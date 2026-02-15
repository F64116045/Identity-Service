import pytest
from typing import Generator
from unittest.mock import MagicMock
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from app.main import app
from app.core.db import get_db, Base
from app.models.user import User 
from sqlalchemy.pool import StaticPool
from app.core.limiter import limiter
# -----------------------------------------------------------------------------
# DATABASE SETUP
# Use an in-memory SQLite database for fast, isolated testing.
# "check_same_thread=False" is required for SQLite when used with FastAPI.
# -----------------------------------------------------------------------------
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# -----------------------------------------------------------------------------
# FIXTURES
# -----------------------------------------------------------------------------

@pytest.fixture(scope="session")
def db_engine():
    """
    Creates the database engine for the entire test session.
    """
    return engine

@pytest.fixture(scope="function")
def db_session(db_engine) -> Generator[Session, None, None]:
    """
    Creates a fresh database session for each test function.
    1. Creates all tables.
    2. Yields the session.
    3. Drops all tables after the test finishes to ensure a clean state.
    """
    # Create tables
    Base.metadata.create_all(bind=db_engine)
    
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        # Drop tables to clean up
        Base.metadata.drop_all(bind=db_engine)

@pytest.fixture(scope="module")
def mock_redis():
    """
    Mocks the Redis client to prevent connection errors during tests.
    This patch is applied at the module level where AuthService is imported.
    """
    with pytest.MonkeyPatch.context() as m:
        mock_client = MagicMock()
        # Configure the mock to return specific values if needed
        mock_client.get.return_value = None
        mock_client.setex.return_value = True
        
        # PATCH TARGET: 
        # You must patch the 'redis_client' where it is USED/IMPORTED, 
        # not where it is defined.
        # Assuming your AuthService is in app.services.auth_service
        m.setattr("app.services.auth_service.redis_client", mock_client)
        
        # Also patch the router's redis_client if it's still being used there directly
        # m.setattr("app.api.v1.endpoints.auth.redis_client", mock_client)
        
        yield mock_client

@pytest.fixture(scope="function")
def client(db_session: Session, mock_redis) -> Generator[TestClient, None, None]:
    """
    Creates a FastAPI TestClient with dependencies overridden.
    Overrides 'get_db' to use the SQLite testing session.
    """
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    # Override the dependency
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as c:
        yield c
    
    # Clean up overrides
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def disable_rate_limiter():
    """
    Mock the rate limiter to be disabled during tests.
    This prevents the tests from trying to connect to a real Redis instance
    for rate limiting, which causes ConnectionRefusedError in CI/CD.
    """

    original_enabled = limiter.enabled
    
    limiter.enabled = False
    
    yield
    
    limiter.enabled = original_enabled