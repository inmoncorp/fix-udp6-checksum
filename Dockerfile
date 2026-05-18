# ==========================================
# Stage 1: Build Environment
# ==========================================
FROM quay.io/centos/centos:stream9 AS builder

# Enable the CRB repository to expose libbpf-devel, then install toolchain
RUN dnf config-manager --set-enabled crb && \
    dnf install -y \
    clang \
    llvm \
    elfutils-libelf-devel \
    glibc-devel \
    libbpf-devel \
    && dnf clean all

WORKDIR /build

# Copy the modified C source code into the container
COPY fix_checksum.c .

# Compile targeted at the BPF architecture 
RUN clang -O2 -g -target bpf -c fix_checksum.c -o fix_checksum.o

# ==========================================
# Stage 2: Minimal Artifact Output
# ==========================================
FROM scratch AS export

# Copy only the compiled object file out of the build layer
COPY --from=builder /build/fix_checksum.o /fix_checksum.o

