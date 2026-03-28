FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy source code
COPY server.py .
COPY src/ src/

EXPOSE 8000

CMD ["python", "server.py"]
