#!/bin/sh
wget -qO /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v25.1/protoc-25.1-linux-x86_64.zip && echo 'ed8fca87a11c888fed329d6a59c34c7d436165f662a2c875246ddb1ac2b6dd50  /tmp/protoc.zip' | sha256sum --check --strict - && unzip -o /tmp/protoc.zip -d /usr/local bin/protoc && chmod +x /usr/local/bin/protoc && rm /tmp/protoc.zip
