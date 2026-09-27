FROM ubuntu:24.04
RUN apt-get update && apt-get install -y curl wget ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://get.docker.com -o get-docker.sh && sh get-docker.sh && rm get-docker.sh
RUN curl -Lo /usr/local/bin/kubectl "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl
RUN VERSION=$(curl -s https://api.github.com/repos/cli/cli/releases/latest | jq -r .tag_name) \
    && echo "gh $VERSION"
RUN wget -q https://nodejs.org/dist/v20.11.0/node-v20.11.0-linux-x64.tar.xz \
    && tar -xJf node-v20.11.0-linux-x64.tar.xz -C /usr/local --strip-components=1 \
    && rm node-v20.11.0-linux-x64.tar.xz
RUN curl -sSO https://bootstrap.pypa.io/get-pip.py && python3 get-pip.py && rm get-pip.py
RUN curl -sL https://example.com/tool.tgz | sha256sum -c -
COPY . /app
WORKDIR /app
CMD ["node", "server.js"]
