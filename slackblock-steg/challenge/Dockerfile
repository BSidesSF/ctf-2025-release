FROM debian:bookworm
RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev

RUN mkdir /app

COPY ./slackblock-steg.py /app

WORKDIR /app

RUN pip3 install --break-system-packages Flask Pillow

RUN useradd -r ctf -u 1000

RUN chown -R root:ctf /app
RUN chmod -R ug+rwX /app

EXPOSE 8888

USER 1000

ENTRYPOINT [ "python3" ]

CMD [ "slackblock-steg.py" ]
