FROM rustlang/rust:nightly
RUN apt update -qy
RUN apt install -qy libclang-dev build-essential pkg-config clang nettle-dev gettext zsh

RUN useradd -u 1000 -d /home/user user && mkdir /home/user && chown user:user /home/user
USER user

RUN rustup install 1.70.0

WORKDIR /home/user/src
