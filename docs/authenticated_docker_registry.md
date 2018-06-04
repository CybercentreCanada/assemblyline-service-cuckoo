# Authenticated Docker Registry

Below are instructions for an Nginx based proxy for domain support.example.com listening on port 8443.

First generate a new pki key, note that docker requires the CN to be the domain of the support server.

    mkdir certs
    openssl req -newkey rsa:4096 -nodes -sha256 \
    -subj '/CN=support.example.com/O=../C=..'
    -keyout certs/support.example.com.key -x509 \
    -days 365 -out certs/support.example.com.cert
    
    cp certs/support.example.com.cert /usr/local/share/ca-certificates/support.example.com.crt
    update-ca-certificates
    
    mkdir /etc/docker/certs.d/support.example.com:8443
    cp certs/support.example.com.cert /usr/local/share/ca-certificates/support.example.com.cert
    cp certs/support.example.com.key /usr/local/share/ca-certificates/support.example.com.key
    chown -R root:root /etc/docker/certs.d/support.example.com:8443
    chmod -R go-rwx /etc/docker/certs.d/support.example.com:8443
    ln -s /etc/docker/certs.d/support.example.com:8443 /etc/docker/certs.d/support.example.com_8443

Note that the final link is created to avoid issues surrounding colons in a filename. Next create some users and 
passwords. I generate passwords with `dd if=/dev/urandom bs=33 count=1 2> /dev/null| base64` but in the example below 
password is used as a password for brevity.

    mkdir auth
    docker run --rm --entrypoint htpasswd registry:2 -Bbn admin password >> auth/htpasswd
    docker run --rm --entrypoint htpasswd registry:2 -Bbn user password >> auth/htpasswd
    cp auth/htpasswd /etc/nginx/docker.htpasswd

You will need to save the following nginx configuration file in /etc/nginx/sites-enabled/docker-proxy

    upstream docker-registry {
      server 127.0.0.1:8443;
    }
    
    server {
      listen                          10.80.30.10:8443 ssl;
      server_name                     support.example.com;
      ssl_certificate                 /etc/docker/certs.d/support.example.com_8443/ca.cert;
      ssl_certificate_key             /etc/docker/certs.d/support.example.com_8443/ca.key;
    
      ssl_protocols TLSv1.1 TLSv1.2;
      ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH';
      ssl_prefer_server_ciphers on;
      ssl_session_cache shared:SSL:10m;
    
      client_max_body_size            0;
      chunked_transfer_encoding       on;
    
      proxy_set_header Host           $http_host;
      proxy_set_header X-Real-IP      $remote_addr;
      proxy_set_header Authorization  "";
    
      location /v2/ {
        auth_basic                    "Docker Registry";
        auth_basic_user_file          /etc/nginx/docker.htpasswd;
        error_log                     /var/log/nginx/docker.log;
    
        proxy_buffering off;
        proxy_pass                          https://docker-registry;
        proxy_read_timeout                  900;
        proxy_set_header  X-Real-IP         $remote_addr; # pass on real client's IP
        proxy_set_header  X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header  X-Forwarded-Proto $scheme;
    
        set $check 'U';
    
        if ($remote_user = "admin") {
          set $check "";
        }
        if ($request_method !~* "^(GET|HEAD)$") {
          set $check "${check}A";
        }
        if ($check = "UA") {
          # not admin and not GET/HEAD
          return 403;
        }
      }
      location / {
        return 403;
      }
    }

After restarting Nginx, launch the docker registry with the following command.

    docker run -d -p 127.0.0.1:8443:5000 --restart=always --name registry \
     -v /etc/docker/certs.d/support.example.com_8443:/certs:ro \
     -e REGISTRY_HTTP_TLS_CERTIFICATE=/certs/ca.cert \
     -e REGISTRY_HTTP_TLS_KEY=/certs/ca.key registry:2

You will need to add the following lines to your seed. 

    seed['installation']['docker']['private_registry'] = 'support.example.com:8443'
    seed['installation']['docker']['private_registry_key'] = """
        Contents of /usr/local/share/ca-certificates/support.example.com.cert
    """
    seed['installation']['docker']['private_registry_auth'] = "user:password".encode('base64').strip()

And you will need to re-run the Cuckoo installer.py to install the certificates and credentials on each worker.