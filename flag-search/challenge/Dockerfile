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

# Copy up the binary and banner
COPY src/flag-search src/banner.txt $APP_HOME/
RUN chown root:root $APP_HOME/flag-search
RUN chmod 0755 $APP_HOME/flag-search
RUN chown root:root $APP_HOME/banner.txt
RUN chmod 0444 $APP_HOME/banner.txt


# Switch to our user
USER 1000

EXPOSE 11010

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:11010,reuseaddr,fork", "EXEC:'/home/ctf/flag-search',pty,stderr,setsid,sane"]
