FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir .

# Copy source code
COPY server.py .
COPY src/ src/

# Suppress FastMCP Rich banner in container logs
ENV FASTMCP_SHOW_SERVER_BANNER=false

EXPOSE 8000

CMD ["python", "server.py"]
