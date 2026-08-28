# Multi-stage build for smaller image size
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set Python to run in unbuffered mode (logs appear immediately in Container Apps)
ENV PYTHONUNBUFFERED=1

# Copy requirements first (for better layer caching)
COPY requirements.txt .

# Install dependencies
# --no-cache-dir reduces image size by not storing pip's cache
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .

# Create a non-root user for security
# Prevents container from running as root
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 8080

# Health check
# Allows Azure Container Apps to monitor and auto-restart unhealthy containers
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health').read()" || exit 1

# Run the application
CMD ["python", "app.py"]
