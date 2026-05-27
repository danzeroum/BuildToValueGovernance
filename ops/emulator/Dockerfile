# Emulador local do gateway BuildToValue.
# A tag da imagem deve ser o SHA do commit (ver Makefile alvo `emulator-up`).
# Build forçado a cada PR aprovada para garantir sincronia com o kernel.

FROM rust:1.78-slim AS builder
WORKDIR /src
COPY rust ./rust
WORKDIR /src/rust
RUN cargo build --release -p buildtovalue-kernel -p btv-cli

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/rust/target/release/btv-cli /usr/local/bin/btv-cli

ENV BTV_EMULATOR_PORT=8080
EXPOSE 8080

# Placeholder: substitua pelo binário do gateway quando publicado.
# Por ora, o emulador apenas expõe o CLI para o tutorial 03.
CMD ["btv-cli", "--help"]
