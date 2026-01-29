FROM python:3.12-slim

# Install system dependencies (ca-certificates for HTTPS)
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Install uv via pip - This is the most reliable way to ensure it's in the PATH
RUN pip install --no-cache-dir uv

# Set working directory
WORKDIR /app

# Enable bytecode compilation for performance
ENV UV_COMPILE_BYTECODE=1

# Copy dependency files first
COPY pyproject.toml uv.lock ./

# Install dependencies without installing the project itself
# We create a virtualenv in /app/.venv
RUN uv sync --frozen --no-install-project

# Ensure the virtualenv is used for subsequent commands
ENV PATH="/app/.venv/bin:$PATH"

# Copy the rest of the application code
COPY . .

# Final sync to install the project
RUN uv sync --frozen

# Default command
CMD ["uv", "run", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]