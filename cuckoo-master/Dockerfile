FROM ubuntu:latest
MAINTAINER cccs-kevin kevin.hardy-cooper@cyber.gc.ca

ENV host_public_ip=10.0.0.5
ENV DEBIAN_FRONTEND=noninteractive
ENV machinery=vmware

#RUN mkdir ~/.gnupg
#RUN echo "disable-ipv6" >> ~/.gnupg/dirmngr.conf
#RUN apt-get -y update \
#    && apt-get install -y --no-install-recommends apt-utils \
#    && apt-get install -y gnupg2

# Add the PostgreSQL PGP key to verify their Debian packages.
# It should be the same key as https://www.postgresql.org/media/keys/ACCC4CF8.asc
#RUN apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8

# Add PostgreSQL's repository. It contains the most recent stable release
#     of PostgreSQL, ``9.3``.
#RUN echo "deb http://apt.postgresql.org/pub/repos/apt/ precise-pgdg main" > /etc/apt/sources.list.d/pgdg.list

# Compile and install packages required prior to Cuckoo
#RUN apt-get -y update \
#    && apt-get -y upgrade \
#    && apt-get install -y python \
#    python-pip \
#    python-dev \
#    libffi-dev \
#    libssl-dev \
#    python-virtualenv \
#    python-setuptools \
#    libjpeg-dev \
#    zlib1g-dev \
#    swig \
#    tcpdump \
#    apparmor-utils \
#    postgresql \
#    libpq-dev \
#    software-properties-common \
#    postgresql-9.3 \
#    postgresql-client-9.3 \
#    postgresql-contrib-9.3 \
#    wget;

# Run the rest of the commands as the ``postgres`` user created by the ``postgres-9.3`` package when it was ``apt-get installed``
#USER postgres
#
## Adjust PostgreSQL configuration so that remote connections to the
## database are possible.
#RUN echo "host all  all    0.0.0.0/0  md5" >> /etc/postgresql/9.3/main/pg_hba.conf
#
## And add ``listen_addresses`` to ``/etc/postgresql/9.3/main/postgresql.conf``
#RUN echo "listen_addresses='*'" >> /etc/postgresql/9.3/main/postgresql.conf
#
## Expose the PostgreSQL port
#EXPOSE 5432
#
## Set the default command to run when starting the container
##CMD ["/usr/lib/postgresql/9.3/bin/postgres", "-D", "/var/lib/postgresql/9.3/main", "-c", "config_file=/etc/postgresql/9.3/main/postgresql.conf"]
#
#USER root
#
## Compile and install Cuckoo and setup PostgreSQL database
#RUN adduser cuckoo \
#    && pip install -U pip setuptools cryptography psycopg2 \
#    && pip install -U git+https://github.com/cccs-kevin/cuckoo.git@cuckoo-azure \
#    && sed -i 's/machinery = virtualbox/machinery = ${machinery}/' .cuckoo/conf/cuckoo.conf \
#    && sed -i 's/ip = 192.168.56.1/ip = ${host_public_ip}/' .cuckoo/conf/cuckoo.conf \
#    && cuckoo -d \
#    && cuckoo community;
#
#
## Startup Script Stuff
#
## Create a PostgreSQL role named ``docker`` with ``docker`` as the password and
## then create a database `docker` owned by the ``docker`` role.
## Note: here we use ``&&\`` to run commands one after the other - the ``\``
##       allows the RUN command to span multiple lines.
#RUN    /etc/init.d/postgresql start &&\
#    psql --command "CREATE USER cuckoo WITH SUPERUSER PASSWORD 'password';" &&\
#    psql --command "CREATE DATABASE cuckoo;" &&\
#    psql --command "GRANT ALL PRIVILEGES ON DATABASE cuckoo to cuckoo;";
#
## Cuckoo daemon
#CMD ["cuckoo", "&"]
#
## Cuckoo reporting processes
#CMD for i in range(3); do ["cuckoo", "process", "instance${i}", "&"]; done
#
## Cuckoo API server
#CMD ["cuckoo", "--debug", "api", "-H", "${host_public_ip}", "&"]
USER root
RUN apt-get update -y -qq \
    && apt-get install -y python-dev libffi-dev libssl-dev \
    && apt-get install -y swig libpq-dev libmysqlclient-dev rar\
    && apt-get install -y libcairo2-dev libpng-dev libossp-uuid-dev \
    && apt-get install -y libfreerdp-dev libjpeg-turbo8-dev \
    && apt-get install -y wget git python-pip postgresql libpq-dev

# Install guacd.
#RUN wget http://archive.apache.org/dist/guacamole/0.9.14/source/guacamole-server-0.9.14.tar.gz \
#    && tar xvf guacamole-server-0.9.14.tar.gz && cd guacamole-server-0.9.14 \
#    && ./configure --with-init-dir=/etc/init.d && make && sudo make install && sudo ldconfig && cd ../

# Postgres Configs
#        psql -U postgres -c "CREATE USER cuckoo WITH PASSWORD 'cuckoo'"
#        psql -U postgres -c "CREATE DATABASE cuckootest"
#        psql -U postgres -c "CREATE DATABASE cuckootest060"
#        psql -U postgres -c "CREATE DATABASE cuckootest11"
#        psql -U postgres -c "CREATE DATABASE distcuckootest"
#        psql -U postgres -c "CREATE DATABASE cuckootestimport"
#        psql -U postgres cuckootestimport <tests/files/sql/11pg.sql >/dev/null

RUN pip install -U pip setuptools

# Compile and install Cuckoo and setup PostgreSQL database
RUN adduser cuckoo \
    && pip install -U pip setuptools \
    && git clone --single-branch --branch cuckoo-azure-2 https://github.com/cccs-kevin/cuckoo.git \
    && cd cuckoo \
    && python stuff/monitor.py \
    && python setup.py sdist \
    && pip install cuckoo;

RUN cuckoo -d \
    && sed -i 's/machinery = virtualbox/machinery = ${machinery}/' .cuckoo/conf/cuckoo.conf \
    && sed -i 's/ip = 192.168.56.1/ip = ${host_public_ip}/' .cuckoo/conf/cuckoo.conf \
    && cuckoo.py community;

# INetSim stuff

