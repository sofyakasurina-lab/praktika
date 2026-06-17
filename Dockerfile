# ─── Build stage ──────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

# Устанавливаем зависимости (bcrypt собираем вручную из исходников)
RUN apt-get update && apt-get install -y \
    build-essential cmake git \
    libboost-all-dev \
    libssl-dev \
    libpqxx-dev \
    nlohmann-json3-dev \
    libasio-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Собираем libbcrypt из исходников (в репозитории Ubuntu его нет)
RUN git clone https://github.com/trusch/libbcrypt.git /tmp/libbcrypt \
 && cmake -S /tmp/libbcrypt -B /tmp/libbcrypt/build -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/libbcrypt/build -j$(nproc) \
 && cmake --install /tmp/libbcrypt/build --prefix /usr/local \
 && rm -rf /tmp/libbcrypt

# Устанавливаем Crow (header-only)
RUN git clone --depth=1 https://github.com/CrowCpp/Crow.git /tmp/Crow \
 && cp -r /tmp/Crow/include/* /usr/local/include/ \
 && rm -rf /tmp/Crow

# Устанавливаем jwt-cpp (header-only)
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

# Только runtime-зависимости (без dev-заголовков)
RUN apt-get update && apt-get install -y \
    libpqxx-7.8t64 \
    libssl3 \
    libboost-system1.83.0 \
    && rm -rf /var/lib/apt/lists/*

# Копируем собранный bcrypt из builder-стадии
COPY --from=builder /usr/local/lib/libbcrypt* /usr/local/lib/
RUN ldconfig

COPY --from=builder /usr/local/bin/ticket_server /usr/local/bin/ticket_server
COPY frontend/ /usr/share/ticket-system/www/

EXPOSE 8080
ENV PORT=8080

CMD ["/usr/local/bin/ticket_server"]