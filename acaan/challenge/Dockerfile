FROM debian:bookworm

RUN apt-get update
RUN apt-get install -y socat

# This is where everything lives
ENV APP_HOME /home/ctf
WORKDIR $APP_HOME

# Copy up the binary
COPY src/acaan $APP_HOME/acaan
RUN chmod 0555 $APP_HOME/acaan

# Copy up the flag
COPY src/flag.txt /flag.txt
RUN chown root:root /flag.txt
RUN chmod 0444 /flag.txt

RUN useradd -r ctf -u 1000
USER 1000

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:4113,reuseaddr,fork", "EXEC:'/home/ctf/acaan'"]
