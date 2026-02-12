# Identity Management Service

A robust authentication service for microservices, fully OIDC-compliant.
Supports asymmetric encryption (RS256) signing, modern OAuth2 flows, rate limiting, and a complete observability stack (PLG), all managed using Infrastructure as Code (IaC) principles.

## System Architecture

The system follows a microservices-ready architecture, utilizing containerization for consistent deployment.

```mermaid
flowchart TD
    User([Client User Agent])

    subgraph Application_Layer
        API[FastAPI Identity Service]
        Worker[[Celery Worker]]
    end

    subgraph Security_Infrastructure
        Keys[RSA Key Pair]
        JWKS["/.well-known/jwks.json"]
    end

    subgraph Data_Infrastructure
        Redis[(Redis Cache & Broker)]
        PG[(PostgreSQL Database)]
    end

    subgraph Observability_Stack
        Promtail((Promtail Agent))
        Loki[(Loki Log Store)]
        Prometheus[(Prometheus TSDB)]
        Grafana{{Grafana Dashboard}}
    end

    User -->|Login Credentials| API
    API -->|Sign Token RS256| Keys
    User -->|Fetch Public Key| JWKS
    
    API --> Redis
    API --> PG

    API -.->|Dispatch Task| Redis
    Redis -.->|Consume Task| Worker
    Worker --> PG

    Prometheus -->|Pull Metrics| API
    Promtail -.->|Tail JSON Logs| API
    Promtail -->|Push Logs| Loki
    Grafana --> Prometheus
    Grafana --> Loki
```

## Key Technical Features

### Security & Authentication

- **Asymmetric Cryptography (RS256)**: Migrated from shared secrets (HS256) to **RSA Public/Private Key pairs**. Tokens are signed with a private key, allowing any downstream microservice to verify integrity using the public key without contacting the IDP.
- **JWKS & OIDC Discovery**: Implements standard `/.well-known/jwks.json` and `openid-configuration` endpoints, enabling seamless integration with third-party resource servers and frontend frameworks.
- **Key Rotation Support**: Tokens include `kid` (Key ID) headers to support zero-downtime key rotation strategies.
- **OAuth2 Authorization Code Flow with PKCE**: Implements Proof Key for Code Exchange (PKCE) to prevent code interception attacks, ensuring secure mobile and SPA integrations.
- **State Parameter Validation**: Strictly enforces state validation during OAuth2 callbacks to mitigate Cross-Site Request Forgery (CSRF) attacks.

### Performance & Scalability

- **Background Task Processing**: Decouples blocking operations (email delivery) from the main request-response cycle using Celery and Redis.
- **Database Connection Pooling**: Optimized SQLAlchemy configuration with connection pooling to reduce handshake overhead and manage database load efficiently.
- **Rate Limiting**: Redis-backed fixedwindow algorithm prevents API abuse and ensures service availability.


### Observability (PLG Stack)

- **Infrastructure as Code (IaC)**: Grafana dashboards and datasources are automatically provisioned via configuration files, eliminating manual setup.
- **Centralized Logging**: Promtail aggregates container logs to Loki, enabling real-time log querying and correlation with metrics.
- **Business Metrics**: Custom Prometheus exporters track critical KPIs such as login success/failure rates, token refresh latency, and active database connections.

![img1](./imgs/dashboard1.png)
![img2](./imgs/dashboard2.png)


## Project Structure

```bash
.
├── app/                  # Application Source Code
│   ├── api/              # Route Handlers
│   ├── core/             # Security configs (OAuth, PKCE, JWT)
│   ├── services/         # Business Logic
│   └── workers/          # Celery Task Definitions
├── grafana/              # Observability Configuration
│   ├── provisioning/     # Automated setup for Datasources & Dashboards
│   └── dashboards_json/  # Exported Dashboard Models
├── docker-compose.yml    # Orchestration
└── promtail-config.yaml  # Log Shipping Rules
```

## Tech Stack Overview

- **Core**: Python 3.12, FastAPI, Pydantic v2
- **Data Layer**: PostgreSQL 16 (Persistence), Redis 7 (Cache/Broker)
- **Task Queue**: Celery, Flower
- **Monitoring**: Prometheus, Loki, Promtail, Grafana
- **Deployment**: Docker, Docker Compose

## Quick Start

### Prerequisites

- Docker & Docker Compose
- OpenSSL (for generating keys)

### 1. Configuration & Key Generation

Clone the repository and configure the environment variables:

```bash
cp .env.example .env
```

**Generate RSA Key Pair (Critical Step):**

Since this project uses RS256, you must generate signing keys before starting.

```bash
mkdir certs
# 1. Generate Private Key
openssl genrsa -out certs/private.pem 2048
# 2. Extract Public Key
openssl rsa -in certs/private.pem -pubout -out certs/public.pem
```

### 2. Deployment

Start the entire stack (Application, Database, Workers, and Monitoring) in detached mode:

```bash
docker compose up -d --build
```

### 3. Service Access

| **Service** | **Endpoint** | **Description** |
| --- | --- | --- |
| **API Documentation** | `http://localhost:8000/docs` | Swagger UI |
| **JWKS Endpoint** | `http://localhost:8000/.well-known/jwks.json` | Public Keys for Token Verification |
| **OIDC Config** | `http://localhost:8000/.well-known/openid-configuration` | OIDC Discovery |
| **Grafana** | `http://localhost:3000` | Monitoring Dashboard (Default: admin/admin) |
| **Prometheus** | `http://localhost:9090` | Metrics Scraper |
| **Flower** | `http://localhost:5555` | Celery Worker Monitor |

## Monitoring & Troubleshooting

**Accessing Structured Logs:**

Logs are aggregated in Grafana (Loki). You can query specific authentication events using LogQL:

`{app="identity-service"} | json | event="auth.token_revoked"`

**Metrics:**

Business metrics such as `identity_auth_events_total` are available in Prometheus and visualized in Grafana.