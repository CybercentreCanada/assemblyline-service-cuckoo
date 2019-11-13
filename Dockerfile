FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH cuckoo.Cuckoo

# Get required apt packages
RUN apt-get update && apt-get install -y \
  qemu-utils

RUN pip install \
  jinja2 \
  retrying \
  pefile

# Switch to assemblyline user
USER assemblyline

# Copy Cuckoo service code
WORKDIR /opt/al_service
COPY . .