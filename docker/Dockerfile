# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y build-essential libpq-dev && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY .. /app

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000
ENV PYTHONUNBUFFERED=1

# Persistente: usa un volume per il database SQLite
VOLUME ["/app/dbdata"]
ENV DATABASE_URL=sqlite:////app/dbdata/cvewatcher.db

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
