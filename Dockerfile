FROM python:3.11-slim

WORKDIR /app

#RUN apt update
#RUN apt-get install -f 

RUN useradd -m -s /bin/bash httpd
RUN usermod -aG root httpd
RUN mkdir /var/db
RUN chown root:root /var/db
# in Google cloud, the user than runs a container is a semi-random,
# assigned by Google so we need to make the directory writable
RUN chmod 777 /var/db

# add required Python modules
COPY app/requirements.txt /app/
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY app /app/
RUN chmod 755 /app/start-web-server.sh

USER httpd

# the port uvicorn will be listening in the container
ARG API_PORT
ENV API_PORT=${API_PORT:-8080}

ARG BASE_PATH
ENV BASE_PATH=${BASE_PATH:-"/"}

ARG BSS_CONNECTOR_MODULE
ENV BSS_CONNECTOR_MODULE=${BSS_CONNECTOR_MODULE:-"bss.adapters.example"}

ARG BSS_CONNECTOR_CLASS
ENV BSS_CONNECTOR_CLASS=${BSS_CONNECTOR_CLASS:-"ExampleBSSConnector"}

EXPOSE $API_PORT

CMD ["./start-web-server.sh"]
