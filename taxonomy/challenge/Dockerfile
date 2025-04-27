FROM php:8.2-fpm-alpine

RUN apk add --no-cache nginx sqlite sqlite-dev sqlite-libs php82-sqlite3 && \
    mkdir -p /run/nginx && \
    docker-php-ext-install pdo_sqlite session

COPY nginx.conf /etc/nginx/nginx.conf
COPY app/ /app/
COPY data/ /data/

RUN chown -R root:root /app /data

CMD (php-fpm -D && nginx -g 'daemon off;')
