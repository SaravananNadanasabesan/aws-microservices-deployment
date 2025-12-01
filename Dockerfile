# Use a lightweight Python image
FROM python:3.11-slim

# Set workdir
WORKDIR /app

# Copy dependencies first (for caching)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose Flask/Gunicorn port
EXPOSE 5000

# Run the app with Gunicorn (production-ready)
CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
