import time
import uuid
from typing import Callable, Awaitable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from structlog.contextvars import bind_contextvars, clear_contextvars
from app.core.logging import logger

class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware responsible for:
    1. Generating a unique Request ID and injecting it into the logging context.
    2. Measuring and logging HTTP request latency.
    3. Capturing and logging unhandled exceptions.
    """
    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Clear context from previous requests to prevent data leakage
        clear_contextvars()
        
        # Extract Request ID from headers or generate a new UUID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        bind_contextvars(request_id=request_id)

        start_time = time.perf_counter()
        
        try:
            response = await call_next(request)
        except Exception as exc:
            # Log unhandled exceptions with traceback information
            logger.exception(
                "unhandled_exception", 
                path=request.url.path, 
                error=str(exc)
            )
            raise exc from None
        finally:
            process_time = time.perf_counter() - start_time
            # Record performance metrics for every completed request
            logger.info(
                "http_access",
                method=request.method,
                path=request.url.path,
                status=response.status_code if 'response' in locals() else 500,
                duration=f"{process_time:.4f}s",
                client_ip=request.client.host if request.client else "unknown"
            )

        # Attach Request ID to the response header for client-side debugging
        response.headers["X-Request-ID"] = request_id
        return response