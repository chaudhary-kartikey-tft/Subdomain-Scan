FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your app
COPY scanner.py .

# Run the script automatically
ENTRYPOINT ["python", "scanner.py"]
