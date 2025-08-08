FROM python:3.11-bookworm

RUN apt-get update && apt-get install -y inotify-tools

RUN mkdir -p /usr/src/app
WORKDIR /usr/src/app
COPY . /usr/src/app

RUN pip3 install --no-cache-dir -r requirements.txt

ENTRYPOINT ["/usr/src/app/entrypoint.sh"]