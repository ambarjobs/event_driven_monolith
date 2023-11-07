FROM python:3.11.6-slim-bullseye

# Expose Pudb (debugger) port
EXPOSE 1984

WORKDIR /deploy

COPY . /deploy

# Update image packages.
RUN apt-get update

# Creating and setting a locale file.
RUN apt-get install -y locales
RUN echo "en_US.UTF-8 UTF-8" > /etc/locale.gen
RUN locale-gen en_US.UTF-8

# Install and upgrade pip.
RUN python3 -m pip install --upgrade pip

# Install requirements (you can install manually requirements-dev.txt in your local environment).
RUN pip3 install -r requirements.txt
