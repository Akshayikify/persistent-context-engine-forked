# Use a slim Python image for a lightweight, fast submission
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy all project files into the container
COPY . .

# Ensure the runner script is executable
RUN chmod +x bench/run.sh

# Set the default command to run the benchmark
# Judges can run this container to get the JSON report immediately
ENTRYPOINT ["/bin/bash", "bench/run.sh"]
