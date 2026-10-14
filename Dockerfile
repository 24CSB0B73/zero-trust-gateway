# ---- build stage ------------------------------------------------------------------
FROM ubuntu:24.04 AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build libpq-dev libssl-dev ca-certificates xz-utils \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt .
COPY src src
COPY demo demo
RUN cmake -G Ninja -B build -DZT_BUILD_TESTS=OFF -DCMAKE_BUILD_TYPE=Release \
    && cmake --build build

# ---- runtime stage (small, non-root) ---------------------------------------------
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 libssl3t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home zt
WORKDIR /app
COPY --from=build /src/build/gateway /src/build/demo_service /app/
COPY web /app/web
ENV WEB_DIR=/app/web
USER zt
EXPOSE 8080
CMD ["/app/gateway"]
