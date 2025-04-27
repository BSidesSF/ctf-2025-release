# Dockerfile
FROM tomcat:10.1-jdk17-openjdk

RUN apt update
RUN apt install -y ncat socat curl wget

COPY flag.txt /flag.txt
RUN chmod 0444 /flag.txt

COPY src/target/ROOT-1.0-SNAPSHOT.war /usr/local/tomcat/webapps/ROOT.war
RUN chmod 0444 /usr/local/tomcat/webapps/ROOT.war

RUN useradd -r ctf -u 1000

# These need to be r/w, the rest not so much
RUN mkdir -p /usr/local/tomcat/logs /usr/local/tomcat/work /usr/local/tomcat/temp /usr/local/tomcat/webapps && \
    chown -R ctf:ctf /usr/local/tomcat/logs && \
    chown -R ctf:ctf /usr/local/tomcat/work && \
    chown -R ctf:ctf /usr/local/tomcat/temp && \
    chown -R ctf:ctf /usr/local/tomcat/webapps

USER 1000
EXPOSE 80

CMD ["catalina.sh", "run"]
