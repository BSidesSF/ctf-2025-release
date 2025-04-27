# Pin this exact version because I know it's exploitable
FROM debian@sha256:1aadfee8d292f64b045adb830f8a58bfacc15789ae5f489a0fedcd517a862cb9

RUN apt-get update -y && \
    apt-get install -y socat net-tools ncat build-essential gdb strace ruby python3 vim nano

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME=/home/ctf

# The binary name
ENV BIN_NAME=goto-zero

# Set up the directory
RUN mkdir $APP_HOME
RUN chown ctf:ctf $APP_HOME
WORKDIR $APP_HOME

# Target user
RUN useradd -r target -u 1001

# Copy up the binary
COPY src/$BIN_NAME $APP_HOME/$BIN_NAME
RUN chown target:target $APP_HOME/$BIN_NAME
RUN chmod 0755 $APP_HOME/$BIN_NAME
RUN chmod +s $APP_HOME/$BIN_NAME

# Copy up the flag
COPY flag.txt $APP_HOME/flag.txt
RUN chown target:target $APP_HOME/flag.txt
RUN chmod 0400 $APP_HOME/flag.txt

# Debugging
# COPY src/$BIN_NAME $APP_HOME/$BIN_NAME
# RUN chown ctf:ctf $APP_HOME/$BIN_NAME
# RUN chmod 0755 $APP_HOME/$BIN_NAME
#
# # Copy up the flag
# COPY flag.txt $APP_HOME/flag.txt
# RUN chown ctf:ctf $APP_HOME/flag.txt

# Switch to our user
USER 1000

EXPOSE 4445

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:4445,reuseaddr,fork", "EXEC:'/bin/bash',pty,stderr,setsid,sane"]

# You can build and start a testing copy of this container with something like:
# docker buildx build . --progress=plain -t test && docker run --rm -it -p 4445:4445 test

# Once built and started, you can connect to the service to test with something like:
# socat STDIO,raw,echo=0,escape=0x03 TCP:localhost:4445
