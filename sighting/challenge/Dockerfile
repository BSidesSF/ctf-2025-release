FROM php:7.4-fpm

# Install Nginx
RUN apt-get update \
    && apt-get install -y nginx libicu-dev libzip-dev \
    && docker-php-ext-install pdo pdo_mysql intl pcntl zip

# Copy Nginx configuration
COPY nginx.conf /etc/nginx/sites-available/default
RUN chown -R root:root /etc/nginx/sites-available/default

COPY app/ /var/www/html/
RUN chown -R root:root /var/www/html

COPY flag.txt /flag.txt
RUN chown -R root:root /flag.txt

# Expose port 80 for Nginx
EXPOSE 80

# Run as the CTF user
# RUN useradd -r ctf -u 1000
# USER 1000

# Run PHP-FPM and Nginx
CMD ["sh", "-c", "php-fpm & nginx -g 'daemon off;'"]
