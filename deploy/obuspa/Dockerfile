# OB-USP-Agent (BSD-3-Clause), pinned build for dev + CI.
# Build steps from the upstream obuspa Dockerfile.
FROM debian:stable-slim AS build
ARG OBUSPA_REF=59028beba21471d19bd3842ef2632ceb6ca8c7fc   # v11.0.7
ARG LWS_REF=v4.5.8
RUN apt-get update && apt-get -y install --no-install-recommends \
      build-essential autoconf automake libtool pkg-config cmake git ca-certificates \
      libssl-dev libcurl4-openssl-dev libsqlite3-dev zlib1g-dev libmosquitto-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN git clone https://github.com/warmcat/libwebsockets.git && cd libwebsockets \
 && git checkout ${LWS_REF} && cmake -DLWS_WITH_MINIMAL_EXAMPLES=OFF -DLWS_WITHOUT_TESTAPPS=ON . \
 && make -j"$(nproc)" && make install && ldconfig
RUN git clone https://github.com/BroadbandForum/obuspa.git && cd obuspa \
 && git checkout ${OBUSPA_REF} && autoreconf --force --install && ./configure \
 && make -j"$(nproc)" install

FROM debian:stable-slim
RUN apt-get update && apt-get -y install --no-install-recommends \
      libssl3 libsqlite3-0 libcurl4 libmosquitto1 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/libwebsockets.so* /usr/local/lib/
COPY --from=build /usr/local/bin/obuspa /usr/local/bin/obuspa
RUN ldconfig
ENTRYPOINT ["/usr/local/bin/obuspa"]
CMD ["-p", "-v4", "-r", "/etc/obuspa/factory_reset.txt", "-f", "/tmp/usp.db"]
