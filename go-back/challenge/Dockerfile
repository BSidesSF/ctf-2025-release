FROM debian:bookworm

RUN apt-get update
RUN apt-get install -y net-tools ncat socat build-essential gdb strace ruby python3 vim nano

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME /home/ctf

# Set up the directory
RUN mkdir $APP_HOME
RUN chown root:root $APP_HOME
WORKDIR $APP_HOME

# Add a target user
RUN useradd -r target -u 1001

# Copy up the binary, setuid to the target user
COPY src/go-back $APP_HOME/go-back
RUN chown target:target $APP_HOME/go-back
RUN chmod 0755 $APP_HOME/go-back
RUN chmod +s $APP_HOME/go-back

# Copy up the flag, and make sure only target can read it
COPY src/flag.txt $APP_HOME/flag.txt
RUN chown target:target $APP_HOME/flag.txt
RUN chmod 0400 $APP_HOME/flag.txt

RUN mkdir $APP_HOME/src/
RUN chown ctf:ctf $APP_HOME/src/

COPY src/Makefile $APP_HOME/src/Makefile
RUN chown ctf:ctf $APP_HOME/src/Makefile
RUN chmod 0644 $APP_HOME/src/Makefile

COPY src/go-back.c $APP_HOME/src/go-back.c
RUN chown ctf:ctf $APP_HOME/src/go-back.c
RUN chmod 0644 $APP_HOME/src/go-back.c

# Copy the .bash_profile
COPY bash_profile $APP_HOME/.bash_profile
RUN chown ctf:ctf $APP_HOME/.bash_profile
RUN chmod +x $APP_HOME/.bash_profile

# Switch to our user
USER 1000

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:4445,reuseaddr,fork", "EXEC:'/bin/bash -li',pty,stderr,setsid,sane"]
