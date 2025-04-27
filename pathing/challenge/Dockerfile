FROM ruby:3.2.3

COPY app/ /var/www/html/
RUN chown -R root:root /var/www/html

RUN mkdir /app
COPY server.rb /app/server.rb
RUN chown -R root:root /app

COPY flag.txt /flag.txt
RUN chown -R root:root /flag.txt

WORKDIR /var/www/html
EXPOSE 4000

RUN gem install webrick

# Run as the CTF user
RUN useradd -r ctf -u 1000
USER 1000

# Run PHP-FPM and Nginx
CMD ["ruby", "/app/server.rb"]
