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

# Add a target user
RUN useradd -r target -u 1001

# Copy up the binary, setuid to the target user
COPY src/drago-daction $APP_HOME/drago-daction
RUN chown target:target $APP_HOME/drago-daction
RUN chmod 0755 $APP_HOME/drago-daction
RUN chmod +s $APP_HOME/drago-daction

# Copy up a non-setuid version of the binary
COPY src/drago-daction $APP_HOME/drago-daction-demo
RUN chown target:target $APP_HOME/drago-daction-demo
RUN chmod 0755 $APP_HOME/drago-daction-demo

# Copy the dragon-report as well as a backup of it
COPY dragon-report.txt $APP_HOME/dragon-report.txt
RUN chown ctf:ctf $APP_HOME/dragon-report.txt
COPY dragon-report.txt $APP_HOME/dragon-report.txt.bak
RUN chown root:root $APP_HOME/dragon-report.txt.bak

# Copy the .bash_profile
COPY bash_profile $APP_HOME/.bash_profile
RUN chown ctf:ctf $APP_HOME/.bash_profile
RUN chmod +x $APP_HOME/.bash_profile

# Copy up the flag, and make sure only target can read it
COPY flag.txt /flag.txt
RUN chown target:target /flag.txt
RUN chmod 0400 /flag.txt

# Switch to our user
USER 1000

# Start server
ENTRYPOINT ["socat", "TCP-LISTEN:4445,reuseaddr,fork", "EXEC:'/bin/bash -li',pty,stderr,setsid,sane"]
