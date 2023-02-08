FROM rust:slim-buster as builder

WORKDIR /app
COPY Cargo.toml ./
COPY . ./
RUN cargo build --release --bin client

FROM ubuntu:20.04 as runner
COPY --from=builder /app/target/release/client /app/client
#CMD ["sleep","3600"]
CMD ["app/client"]
