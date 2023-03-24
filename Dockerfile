FROM python:3.11-slim

WORKDIR /app

#RUN apt update
#RUN apt-get install -f 
# add required Python modules
COPY ./requirements.txt /app/
RUN pip install --no-cache-dir --upgrade -r requirements.txt

COPY . /app/

# the port uvicorn will be listening in the container
ARG API_PORT
ENV API_PORT=${PORT:-8080}

ARG BASE_PATH
ENV BASE_PATH=${BASE_PATH:-"/"}

EXPOSE $API_PORT

# CMD ["sh", "-c", "uvicorn 'main:app' --host '0.0.0.0' --port ${API_PORT} --root-path ${BASE_PATH}"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
