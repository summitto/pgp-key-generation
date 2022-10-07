FROM ubuntu:22.04 AS build

RUN apt-get update &&            \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install -y             \
  cmake                          \
  gcc                            \
  git                            \
  libboost-all-dev               \
  libcrypto++-dev                \
  libsodium-dev                  \
  make                           \
  pkg-config                     \
  python3-pip

RUN pip3 install dataclasses

RUN git clone https://github.com/summitto/pgp-packet-library.git --depth 1 --recurse-submodules --shallow-submodules /opt/pgp-packet-library

RUN git clone https://github.com/summitto/pgp-key-generation.git --depth 1 --recurse-submodules --shallow-submodules /opt/pgp-key-generation

RUN cd /opt/pgp-packet-library && \
  cmake -B build

RUN cd /opt/pgp-packet-library && \
  make -C build install

WORKDIR /opt/pgp-key-generation

RUN cd /opt/pgp-key-generation && \
  cmake -B build &&               \
  make -C build

FROM ubuntu:22.04
RUN apt-get update &&            \
  DEBIAN_FRONTEND=noninteractive \
  apt-get install -y             \
  libboost-program-options1.74.0 \
  libcrypto++8                   \
  libsodium23

COPY --from=build                                                         \
  /opt/pgp-key-generation/build/generate_derived_key/generate_derived_key \
  /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/generate_derived_key"]
