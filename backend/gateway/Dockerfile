FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

EXPOSE 8765

ENV HOST=0.0.0.0
ENV PORT=8765
ENV REDIS_URL=redis://localhost:6379
ENV REDIS_CHANNEL=aegis-alerts
ENV HEARTBEAT_INTERVAL=30.0

CMD ["python", "main.py"]
