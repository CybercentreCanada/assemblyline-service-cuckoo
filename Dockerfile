ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH cuckoo.cuckoo_main.Cuckoo

USER root

# Get required apt packages
RUN apt-get update && apt-get install -y qemu-utils && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install pip packages
RUN pip install --no-cache-dir --user retrying pefile && rm -rf ~/.cache/pip

# Copy Cuckoo service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
