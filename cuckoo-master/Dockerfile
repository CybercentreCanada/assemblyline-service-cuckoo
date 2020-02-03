FROM ubuntu:latest
MAINTAINER cccs-kevin kevin.hardy-cooper@cyber.gc.ca

ENV host_private_ip=10.1.0.10
ENV host_public_ip=10.0.0.5
ENV DEBIAN_FRONTEND=noninteractive


RUN mkdir ~/.gnupg
RUN echo "disable-ipv6" >> ~/.gnupg/dirmngr.conf
RUN apt-get -y update \
    && apt-get install -y --no-install-recommends apt-utils \
    && apt-get install -y gnupg2

# Add the PostgreSQL PGP key to verify their Debian packages.
# It should be the same key as https://www.postgresql.org/media/keys/ACCC4CF8.asc
RUN apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8

# Add PostgreSQL's repository. It contains the most recent stable release
#     of PostgreSQL, ``9.3``.
RUN echo "deb http://apt.postgresql.org/pub/repos/apt/ precise-pgdg main" > /etc/apt/sources.list.d/pgdg.list

# Compile and install packages required prior to Cuckoo
RUN apt-get -y update \
    && apt-get -y upgrade \
    && apt-get install -y python \
    python-pip \
    python-dev \
    libffi-dev \
    libssl-dev \
    python-virtualenv \
    python-setuptools \
    libjpeg-dev \
    zlib1g-dev \
    swig \
    tcpdump \
    apparmor-utils \
    postgresql \
    libpq-dev \
    software-properties-common \
    postgresql-9.3 \
    postgresql-client-9.3 \
    postgresql-contrib-9.3 \
    wget;

# Run the rest of the commands as the ``postgres`` user created by the ``postgres-9.3`` package when it was ``apt-get installed``
USER postgres

# Create a PostgreSQL role named ``docker`` with ``docker`` as the password and
# then create a database `docker` owned by the ``docker`` role.
# Note: here we use ``&&\`` to run commands one after the other - the ``\``
#       allows the RUN command to span multiple lines.
RUN    /etc/init.d/postgresql start &&\
    psql --command "CREATE USER cuckoo WITH SUPERUSER PASSWORD 'password';" &&\
    psql --command "CREATE DATABASE cuckoo;" &&\
    psql --command "GRANT ALL PRIVILEGES ON DATABASE cuckoo to cuckoo;";

# Adjust PostgreSQL configuration so that remote connections to the
# database are possible.
RUN echo "host all  all    0.0.0.0/0  md5" >> /etc/postgresql/9.3/main/pg_hba.conf

# And add ``listen_addresses`` to ``/etc/postgresql/9.3/main/postgresql.conf``
RUN echo "listen_addresses='*'" >> /etc/postgresql/9.3/main/postgresql.conf

# Expose the PostgreSQL port
EXPOSE 5432

# Add VOLUMEs to allow backup of config, logs and databases
VOLUME  ["/etc/postgresql", "/var/log/postgresql", "/var/lib/postgresql"]

# Set the default command to run when starting the container
CMD ["/usr/lib/postgresql/9.3/bin/postgres", "-D", "/var/lib/postgresql/9.3/main", "-c", "config_file=/etc/postgresql/9.3/main/postgresql.conf"]

USER root

# Compile and install Cuckoo and setup PostgreSQL database
RUN adduser cuckoo \
    && pip install -U pip setuptools \
    && pip install cryptography \
    && pip install -U cuckoo \
    && virtualenv venv \
    && . venv/bin/activate \
    && pip install -U pip setuptools \
    && pip install -U cuckoo \
    && cuckoo -d \
    && cuckoo community \
    && pip install psycopg2;

CMD ["cuckoo", "--debug", "api", "-H", "${host_public_ip}"]