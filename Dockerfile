
FROM ubuntu:22.04

RUN apt-get update
RUN apt-get install -y python3-pip curl
RUN pip3 install matplotlib
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | bash -s -- -y
RUN echo 'source $HOME/.cargo/env' >> $HOME/.bashrc
RUN mkdir -p /notry

COPY . /notry
