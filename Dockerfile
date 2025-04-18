# Use an official Python runtime as a parent image
FROM python:3.11

RUN apt-get update && apt-get install -y docker.io
# Set the working directory
WORKDIR /app

# Copy the application files
COPY . /app

# Install dependencies
RUN pip install --upgrade pip && pip install -r requirements.txt

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development

# Expose port 8001 for Gunicorn
EXPOSE 8001

# Default command to run migrations, create admin, and start the app
# CMD ["sh", "-c", "gunicorn -w 4 -b 0.0.0.0:8001 app:app"]
CMD ["gunicorn", "--reload", "--workers=4", "-b", "0.0.0.0:8001", "app:app"]

