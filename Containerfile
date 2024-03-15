FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY app.py cluster.py microcert.py requirements.txt .

RUN microdnf -y update && \
  microdnf -y install python3.11 python3.11-pip && \
  microdnf clean all && \
  pip3.11 install -U pip && \
  pip3.11 install -U -r requirements.txt

EXPOSE 5000
