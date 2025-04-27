FROM debian:bookworm
RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev socat

RUN mkdir /app

COPY ./flag.txt banner.txt init_state.tar.gz arrow_of_time.py start.sh /app

RUN tar -zx -C /app -f /app/init_state.tar.gz

RUN useradd -r ctf -u 1000

RUN chown -R ctf:ctf /app

USER 1000

EXPOSE 54321

WORKDIR /app
ENTRYPOINT ["/bin/bash"]
CMD ["/app/start.sh"]
