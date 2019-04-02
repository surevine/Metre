FROM debian:sid-slim AS cpp-build

RUN set -eux; \
   apt-get update; \
   apt-get install --quiet --yes --no-install-recommends \
       clang \
       cmake \
       googletest \
       libc++-dev \
       libc++abi-dev \
       libevent-dev \
       libexpat-dev \
       libicu-dev \
       libspdlog-dev \
       libssl-dev \
       libunbound-dev \
       ninja-build \
       pkg-config \
   ; \
   apt-get clean; \
   rm -rf /var/lib/apt/lists/* ;

RUN adduser --system --home /var/cache/metre --shell /sbin/nologin metre

WORKDIR /app/

COPY deps src/deps

COPY cmake src/cmake
COPY gen src/gen
COPY include src/include
COPY src src/src
COPY tests src/tests
COPY CMakeLists.txt src/

RUN set -eux; \
    mkdir build; \
    cd build; \
    CC=clang CXX=clang++ cmake \
        -DCMAKE_INSTALL_PREFIX=/app/install \
        -DCMAKE_BUILD_TYPE=Release \
        -DVENDORED_DEPS=false \
        -GNinja \
        ../src; \
    ninja; \
    ninja test; \
    ninja install

RUN set -eux; \
    mkdir -p /app/deps/; \
    ldd /app/install/bin/metre | awk '$1~/^\//{print $1}$3~/^\//{print $3}' \
        | xargs -I{} cp --parents {} '/app/deps/'




FROM scratch

VOLUME /tmp

COPY --from=cpp-build /etc/passwd /etc/shadow /etc/
COPY --from=cpp-build /app/deps/ /

WORKDIR /app
COPY --from=cpp-build /app/install/bin/metre .

USER metre
ENTRYPOINT ["/app/metre"]
