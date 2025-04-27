FROM php:8.2-fpm

RUN apt update
RUN apt install -y --no-install-recommends nginx ncat curl wget bc

COPY nginx.conf /etc/nginx/nginx.conf
COPY app/ /app/
COPY flag.txt /flag.txt
RUN chown root:root /flag.txt
RUN chmod 0644 /flag.txt

RUN chown -R root:root /app
RUN chmod 0755 /app/valuate-hoard

CMD (php-fpm -D && nginx -g 'daemon off;')
