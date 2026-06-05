# Use an official Python runtime as a parent image
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    iputils-ping \
    libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install project dependencies
RUN pip install --no-cache-dir .

# Grant Nmap extra permissions (if needed on Linux)
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)

# Run the tool when the container launches
ENTRYPOINT ["network-inventory"]
CMD ["--help"]
