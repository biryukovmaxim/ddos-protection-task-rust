FROM rust:slim-buster as builder
RUN rustup install nightly
RUN cargo install bpf-linker

WORKDIR /app
COPY Cargo.lock Cargo.toml ./
COPY . ./

ENV EBPF_PATH=/app/ddos-protection-task
RUN cargo build --release --bin server
#COPY /app/target/bpfel-unknown-none/release/ddos-protection-task /app/ddos-protection-task

FROM ubuntu:20.04 as runner
RUN apt-get update && apt-get install -y build-essential linux-headers-generic libc-dev libbsd-dev sudo
COPY --from=builder /app/target/bpfel-unknown-none/release/ddos-protection-task /app/ddos-protection-task
COPY --from=builder /app/target/release/server /app/server

EXPOSE 5051
EXPOSE 1053

#CMD ["sleep","3600"]
CMD ["app/server"]
