# ─── Build stage ──────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git \
    libboost-all-dev \
    libssl-dev \
    libpqxx-dev \
    libbcrypt-dev \
    nlohmann-json3-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Crow (header-only)
RUN git clone --depth=1 https://github.com/CrowCpp/Crow.git /tmp/Crow \
 && cp -r /tmp/Crow/include/* /usr/local/include/ \
 && rm -rf /tmp/Crow

# Install jwt-cpp (header-only)
RUN git clone --depth=1 https://github.com/Thalhammer/jwt-cpp.git /tmp/jwt-cpp \
 && cp -r /tmp/jwt-cpp/include/* /usr/local/include/ \
 && rm -rf /tmp/jwt-cpp

WORKDIR /build
COPY backend/ .

RUN cmake -B cmake-build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build cmake-build -j$(nproc) \
 && cp cmake-build/ticket_server /usr/local/bin/ticket_server

# ─── Runtime stage ─────────────────────────────────────────────────────────────
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    libpqxx-8.0 \
    libssl3 \
    libbcrypt0 \
    libboost-system1.83.0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/ticket_server /usr/local/bin/ticket_server

# Frontend served as static files (via nginx or directly embedded)
COPY frontend/ /usr/share/ticket-system/www/

EXPOSE 8080
ENV PORT=8080

CMD ["/usr/local/bin/ticket_server"]
