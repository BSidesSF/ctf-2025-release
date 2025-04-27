FROM php:8.2-fpm

RUN apt update
RUN apt install -y --no-install-recommends nginx ncat curl wget

COPY nginx.conf /etc/nginx/nginx.conf
COPY app/ /app/

RUN chown -R root:root /app
RUN chmod 0755 /app/dragon-detector-ai

CMD (php-fpm -D && nginx -g 'daemon off;')
