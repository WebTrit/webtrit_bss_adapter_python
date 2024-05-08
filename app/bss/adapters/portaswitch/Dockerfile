## TODO: copy the content of this Dockerfile to the root Dockerfile of this repository.
## cp app/bss/adapters/portaswitch/Dockerfile Dockerfile
##
## TODO: Fill the environment variables with IP addresses and credentials.
## sudo docker build -t portaswitch .
## sudo docker run -p 8080:8080 portaswitch

FROM python:3.11-slim

RUN mkdir /app
WORKDIR /app

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
RUN chmod 755 /app/entrypoint.sh

USER httpd

ENV API_PORT=8080
ENV BASE_PATH="/"

ENV BSS_ADAPTER_PATH="/app/bss/adapters"
ENV BSS_ADAPTER_MODULE="bss.adapters.portaswitch"
ENV BSS_ADAPTER_CLASS="PortaSwitchAdapter"
ENV DEBUG="True"

ENV PORTASWITCH_ADMIN_API_SERVER="https://<admin-ip>:<admin-port>"
ENV PORTASWITCH_ADMIN_API_USER="<admin-login>"
ENV PORTASWITCH_ADMIN_API_PASSWORD="<admin-password>"
ENV PORTASWITCH_ACCOUNT_API_SERVER="https://<account-ip>:<account-port>"

ENV PORTASWITCH_SIP_SERVER_HOST="<sip-server-ip>"
ENV PORTASWITCH_SIP_SERVER_PORT="<sip-server-port>"

# Shows whether to verify the HTTPs certificate of the PortaSwitch API while accessing it.
ENV PORTASWITCH_VERIFY_HTTPS="False"

# defines the type of account properties used for login, with the following possible values (optional):
# * self-care - login for request and password from response (default value)
# * sip - id for request and h323_password from response
ENV PORTASWITCH_SIGNIN_CREDENTIALS="<signin-credentials>"

EXPOSE $API_PORT

ENTRYPOINT ["./entrypoint.sh"]
CMD ["./start-web-server.sh"]
