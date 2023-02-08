# ddos-protection-task

# Tcp-server protected from syn-flood(ddos) attacks
Basic idea was taken from [the publication]( https://www.csc.kth.se/utbildning/kth/kurser/DD143X/dkand12/Group5Mikael/final/Jonatan_Landsberg_and_Anton_Lundqvist.pdf)
# Glossary

## DDOS

A DDoS attack, which stands for “distributed denial-of-service” is a malicious attempt to disrupt the normal traffic of a targeted server, service or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic.

### [TCP Connection Attacks](https://blog.radware.com/security/2019/11/threat-alert-tcp-reflection-attacks/)

These attempt to use up all the available connections to infrastructure devices such as load-balancers, firewalls and application servers. Even devices capable of maintaining state on millions of connections can be taken down by these attacks.

## [Proof of work](https://en.wikipedia.org/wiki/Proof_of_work)

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Server

```bash
BPF_PATH=target/bpfel-unknown-none/release/ddos-protection-task cargo build --bin server
```

## Run release

```bash
BPF_PATH=target/bpfel-unknown-none/release/ddos-protection-task RUST_LOG=info cargo xtask run
```

# Run in docker(possible only after building ebpf)
## Server
### Server build
```bash
docker build -f ./docker/server/Dockerfile -t 'server:08022023' .
```
### Server run
```bash
docker run  --privileged  --env RUST_LOG=debug --name rust-server --net host server:08022023
```
it's impossible to run the server using bpf without the flag
[issue](https://github.com/falcosecurity/falco/issues/1299)

## Client
### Client build
```bash
docker build -f ./docker/client/Dockerfile -t 'client:08022023' . 
```
### Client run

```bash
docker run --env RUST_LOG=debug --name rust-client --net host client:08022023 
```