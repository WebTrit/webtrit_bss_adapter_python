FROM python:3.11-slim

WORKDIR /tests

#RUN apt update
#RUN apt-get install -f 
# add required Python modules
COPY ./requirements.txt /tests/

RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . /tests/
RUN chmod 755 /tests/run-tests.sh

ENTRYPOINT ["/tests/run-tests.sh"]

CMD ["echo", "Usage: docker run -i <image-name> [--server SERVER_URL] [--username <USER>] [--password <PASSWORD] [--otp <OTP>]" ]

#CMD ["pytest", "-v", "--server", "cloud", "/tests/"]
#CMD ["tail", "-f", "/dev/null"]