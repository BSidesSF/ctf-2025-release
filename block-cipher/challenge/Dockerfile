FROM debian:bookworm

RUN apt-get update -y
#RUN apt-get install -y perl-base libmime-tools-perl graphicsmagick-imagemagick-compat socat
RUN apt-get install -y perl-base libmime-tools-perl imagemagick socat

# The current user
RUN useradd -r ctf -u 1000

# This is where everything lives
ENV APP_HOME=/home/ctf

# Set up the directory
RUN mkdir -p $APP_HOME
RUN chown ctf:ctf $APP_HOME
WORKDIR $APP_HOME

# Copy up the binary
COPY run.sh block-cipher.pl $APP_HOME/
RUN mkdir $APP_HOME/imgs
COPY imgs/*.png $APP_HOME/imgs/
RUN chown root:root $APP_HOME/block-cipher.pl $APP_HOME/run.sh
RUN chmod 0755 $APP_HOME/block-cipher.pl

RUN chown root:root $APP_HOME/imgs/*.png
RUN chmod 0444 $APP_HOME/imgs/*.png

# Switch to our user
USER 1000

EXPOSE 55744

CMD ["/home/ctf/run.sh"]
