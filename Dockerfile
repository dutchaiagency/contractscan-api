FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY services/ services/
RUN mkdir -p evidence
ENV PORT=10000
CMD ["python", "services/x402-api/server.py"]
