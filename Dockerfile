# syntax=docker/dockerfile:1

# Build stage: compilers stay here, only the resulting wheels move on.
FROM python:3.13-slim AS build

RUN apt-get update && \
	apt-get install -y --no-install-recommends build-essential libpq-dev && \
	rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt


FROM python:3.13-slim

RUN apt-get update && \
	apt-get upgrade -y && \
	rm -rf /var/lib/apt/lists/*

COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

WORKDIR /app
COPY . /app

# Code stays root-owned (read-only for the app); /app itself is writable so the
# default SQLite database can be created there.
RUN useradd --system --uid 10001 --no-create-home cvewatcher && \
	chown cvewatcher /app
USER cvewatcher

ENV PYTHONUNBUFFERED=1 \
	PYTHONDONTWRITEBYTECODE=1

EXPOSE 8000

# Alembic migrations run automatically on startup (see app/database/init_schema).

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
