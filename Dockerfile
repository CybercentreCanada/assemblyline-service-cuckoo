FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH cuckoo.cuckoo.Cuckoo

USER root

# Get required apt packages
RUN apt-get update && apt-get install -y qemu-utils && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install pip packages
RUN pip install --no-cache-dir --user jinja2 retrying pefile ip2geotools && rm -rf ~/.cache/pip

# Copy Cuckoo service code
WORKDIR /opt/al_service
COPY . .