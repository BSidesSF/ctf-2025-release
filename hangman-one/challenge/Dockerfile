FROM ubuntu:latest
RUN apt-get update -y && \
  apt-get install -y python3-pip python3-dev

COPY . /app

WORKDIR /app

RUN pip3 install --break-system-packages -r requirements.txt

RUN useradd -r ctf -u 2000
RUN chown -R root:ctf /app
RUN chmod -R ug+rwX /app

EXPOSE 8000

USER 2000

ENTRYPOINT [ "python3" ]

CMD [ "server.py" ]
