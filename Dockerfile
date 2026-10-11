# ==============================================================================
# SOC CHESS — PRODUCTION DOCKERFILE FOR CLOUD DEPLOYMENT (RENDER / AWS / GCP)
# Multi-stage build: React Vite Frontend + FastAPI High-Performance Backend
# ==============================================================================

# STAGE 1: Build React 18 + TypeScript Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci --prefer-offline --no-audit

COPY frontend/ ./
RUN npm run build

# STAGE 2: Python Backend Runtime
FROM python:3.11-slim AS runtime
WORKDIR /app

# Install minimal OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r backend/requirements.txt

# Copy platform source tree
COPY backend/ ./backend/
COPY ml/ ./ml/
COPY datasets/ ./datasets/
COPY models/ ./models/
COPY database/ ./database/
COPY uploads/ ./uploads/

# Copy built frontend production artifacts from Stage 1
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Cloud Environment Configuration
ENV PORT=8001 \
    BACKEND_HOST=0.0.0.0 \
    USE_SQLITE=true \
    AUTH_ENABLED=true \
    PYTHONUNBUFFERED=1

EXPOSE 8001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8001}/api/health || exit 1

# Launch ASGI Server on Render's dynamic $PORT
CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8001}"]
