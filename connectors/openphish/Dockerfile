FROM python:3.11.1-bullseye as base
FROM base as builder

# Run linux updates and package upgrades
RUN apt-get update -y
RUN apt-get upgrade -y

RUN adduser --disabled-password --gecos '' openphish

WORKDIR /home/openphish/
# Install pip
RUN apt-get install pip -y

# Copy requirements and entrypoint to the working directory
COPY src/requirements.txt /home/openphish/requirements.txt
COPY entrypoint.sh /home/openphish/entrypoint.sh
COPY src/main.py /home/openphish/src/main.py
COPY src/config.yml /home/openphish/src/config.yml
COPY src/client.py /home/openphish/src/client.py

# provide execution perfmissions to the entrypoint file
RUN  chmod +x entrypoint.sh

# Install python dependencies
RUN pip3 install -r requirements.txt

# Upgrade pip
RUN pip3 install --upgrade pip

# install chromium dependencies
RUN apt-get install -y libglib2.0-0 \
    libnss3 \
    libgconf-2-4 \
    libfontconfig1


# install chromium
RUN apt-get install chromium -y

USER openphish
RUN ls -al /home/openphish/src

# Expose the entrypoint
ENTRYPOINT ["python3", "/home/openphish/src/main.py"]
