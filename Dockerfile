# syntax=docker/dockerfile:1
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
	apt-get upgrade -y && \
	apt-get install -y --no-install-recommends build-essential libpq-dev && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Expose port (default FastAPI/uvicorn)
EXPOSE 8000

ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=postgresql://cveuser:cvepass@db:5432/cvewatcher

# Run Alembic migrations (optional, comment if not needed)
# RUN alembic upgrade head

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
