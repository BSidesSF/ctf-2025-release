FROM debian:testing AS builder

RUN apt-get update -y && \
    apt-get install -y build-essential

COPY src/ /src

WORKDIR /src

RUN make
RUN mkdir -p /distfiles && cp tasklist /distfiles/tasklist

FROM debian:testing

RUN apt-get update -y && \
    apt-get install -y socat

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME=/home/ctf

# The binary name
ENV BIN_NAME=tasklist

# Set up the directory
RUN mkdir $APP_HOME
RUN chown ctf:ctf $APP_HOME
WORKDIR $APP_HOME

# Copy up the binary
COPY --from=builder /src/$BIN_NAME $APP_HOME/$BIN_NAME
RUN chown root:root $APP_HOME/$BIN_NAME
RUN chmod 0755 $APP_HOME/$BIN_NAME

# Switch to our user
USER 1000

EXPOSE 4444

# Start server
CMD ["socat", "TCP-LISTEN:4444,reuseaddr,fork", "EXEC:'/home/ctf/tasklist',pty,stderr,setsid,sane"]

# You can build and start a testing copy of this container with something like:
# docker buildx build . --progress=plain -t test && docker run --rm -it -p 4444:4444 test

# Once built and started, you can connect to the service to test with something like:
# socat STDIO,raw,echo=0,escape=0x03 TCP:localhost:4444
