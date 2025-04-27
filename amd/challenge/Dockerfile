FROM debian:bookworm
RUN apt-get update -y && \
    apt-get install -y libssl-dev socat

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME=/home/ctf

# Set up the directory
RUN mkdir $APP_HOME
RUN chown ctf:ctf $APP_HOME
WORKDIR $APP_HOME

# Copy up the binary
COPY src/amd $APP_HOME/amd
RUN chown root:root $APP_HOME/amd
RUN chmod 0755 $APP_HOME/amd

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

EXPOSE 8664

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:8664,reuseaddr,fork", "EXEC:'/home/ctf/amd',pty,stderr,setsid,sane"]
