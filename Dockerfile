FROM python:3.8.10

ARG DEBIAN_FRONTEND=noninteractive
ARG DEBCONF_NOWARNINGS=yes

RUN apt-get update -qq
RUN apt-get install -y \
    apt-transport-https \
    build-essential \
    curl \
    tzdata \
    net-tools \
    wget \
    vim

WORKDIR /AMGenerator
COPY . ./

RUN python3 -m pip install --upgrade pip
RUN pip install -r requirements.txt

CMD ["bash", "scripts/run_app_in_docker.sh"]

