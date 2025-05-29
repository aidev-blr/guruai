# Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# Prevent Python from writing .pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Optional: Set Google Cloud Project ID (but preferably via environment variables at deployment)
ENV GOOGLE_CLOUD_PROJECT=my-rag-project-id 
COPY keys/firebase_service_account.json /app/keys/firebase_service_account.json


# Set the working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Cloud Run expects the app to listen on port 8080
EXPOSE 8080

# Optional for Flask, usually not needed with Gunicorn
# ENV FLASK_APP=app.py

# Run the app using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
