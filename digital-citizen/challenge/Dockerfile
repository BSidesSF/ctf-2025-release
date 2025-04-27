FROM debian:bookworm

RUN apt-get update -y && \
    apt-get install -y socat

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME=/home/ctf

# The binary name
ENV BIN_NAME=digital-citizen

# Set up the directory
RUN mkdir $APP_HOME
RUN chown ctf:ctf $APP_HOME
WORKDIR $APP_HOME

# Copy up the binary
COPY src/$BIN_NAME $APP_HOME/$BIN_NAME
RUN chown root:root $APP_HOME/$BIN_NAME
RUN chmod 0755 $APP_HOME/$BIN_NAME

# Copy up the flags and banner
COPY flag_1.txt flag_2.txt src/banner.txt $APP_HOME/
RUN chown root:root $APP_HOME/*.txt
RUN chmod 0444 $APP_HOME/*.txt

# Switch to our user
USER 1000

EXPOSE 6537

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:6537,reuseaddr,fork", "EXEC:'/home/ctf/digital-citizen',pty,stderr,setsid,sane"]

# You can build and start a testing copy of this container with something like:
# docker buildx build . --progress=plain -t test && docker run --rm -it -p 6537:6537 test

# Once built and started, you can connect to the service to test with something like:
# socat STDIO,raw,echo=0,escape=0x03 TCP:localhost:6537
