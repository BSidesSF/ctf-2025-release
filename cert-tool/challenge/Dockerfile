FROM debian:bookworm
RUN apt-get update -y && \
    apt-get install -y libssl-dev socat openssl

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME=/home/ctf

# Set up the directory
RUN mkdir $APP_HOME
RUN chown ctf:ctf $APP_HOME
WORKDIR $APP_HOME

# Copy up the binary
COPY src/cert-tool $APP_HOME/cert-tool
RUN chown root:root $APP_HOME/cert-tool
RUN chmod 0755 $APP_HOME/cert-tool

# Copy up the banner
COPY src/banner.txt $APP_HOME/banner.txt
RUN chown root:root $APP_HOME/banner.txt
RUN chmod 0444 $APP_HOME/banner.txt

# Copy up the flag
COPY flag.txt $APP_HOME/flag.txt
RUN chown root:root $APP_HOME/flag.txt
RUN chmod 0444 $APP_HOME/flag.txt

# Switch to our user
USER 1000

EXPOSE 6464

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:6464,reuseaddr,fork", "EXEC:'/home/ctf/cert-tool',pty,stderr,setsid,sane"]
