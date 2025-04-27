FROM debian:bookworm

RUN apt-get update
RUN apt-get install -y net-tools ncat socat build-essential gdb strace ruby python3 vim nano

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME /home/ctf

# Set up the directory
RUN mkdir $APP_HOME
RUN chown ctf:ctf $APP_HOME
WORKDIR $APP_HOME

# Copy up the binary
COPY src/bug-me $APP_HOME/bug-me
RUN chown root:root $APP_HOME/bug-me
RUN chmod 0755 $APP_HOME/bug-me

# Copy the .bash_profile
COPY bash_profile $APP_HOME/.bash_profile
RUN chown ctf:ctf $APP_HOME/.bash_profile
RUN chmod +x $APP_HOME/.bash_profile

# Switch to our user
USER 1000

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:4445,reuseaddr,fork", "EXEC:'/bin/bash -li',pty,stderr,setsid,sane"]
