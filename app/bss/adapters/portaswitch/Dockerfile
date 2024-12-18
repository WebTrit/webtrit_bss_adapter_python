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

# Defines contacts list selection mode, with the following possible values (optional):
# * accounts - account info from get_accounts_list API response (default value)
# * extensions - extension info from get_extensions_list API response
ENV PORTASWITCH_CONTACTS_SELECTING="<contacts-selecting>"

# Defines a list of extension types for PORTASWITCH_CONTACTS_SELECTING=extensions mode, with the following possible values (optional):
# * Account - extension type from response should be Account
# * Group - extension type from response should be Group
# * Unassigned - extension type from response should be Unassigned
# By default does not apply filter by type
ENV PORTASWITCH_CONTACTS_SELECTING_EXTENSION_TYPES="Account, Group, Unassigned"

# Ensures that the contacts API filters accounts that do not have an `extension_id` (optional):
ENV PORTASWITCH_CONTACTS_SKIP_WITHOUT_EXTENSION="True"

# Defines list of the account's ids (i_account) which can use any OTP verification code for authentication - usually used for demo purposes (optional):
ENV PORTASWITCH_OTP_IGNORE_ACCOUNTS="6088"

# Ensures that the user info API hides the user balance (optional):
ENV HIDE_BALANCE_IN_USER_INFO="True"

ENV PORTASWITCH_SELF_CONFIG_PORTAL_URL="https://portaone-self-config.onrender.com/"

EXPOSE $API_PORT

ENTRYPOINT ["./entrypoint.sh"]
CMD ["./start-web-server.sh"]
