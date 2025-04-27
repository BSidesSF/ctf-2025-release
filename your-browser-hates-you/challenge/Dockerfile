# Use the official Nginx image as a base
FROM nginx:1.7

# Generate a self-signed certificate
#RUN apk add openssl
RUN mkdir -p /etc/nginx/ssl/
#RUN openssl req -x509 -newkey rsa:512 -nodes -keyout /etc/nginx/ssl/nginx-selfsigned.key -out /etc/nginx/ssl/nginx-selfsigned.crt -days -1 -subj "/C=US/ST=State/L=Locality/O=Organization/CN=localhost" -md5
COPY cert/ /etc/nginx/ssl

# Copy the Nginx configuration file into the container
COPY nginx.conf /etc/nginx/nginx.conf
COPY app/ /usr/share/nginx/html

# Expose port 443 for HTTPS
EXPOSE 443

# lint:no-cmd
