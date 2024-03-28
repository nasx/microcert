FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY app.py cluster.py microcert.py requirements.txt .

RUN microdnf -y update && \
  microdnf -y install python3.11 python3.11-pip && \
  microdnf clean all && \
  pip3.11 install -U pip && \
  pip3.11 install -U -r requirements.txt

EXPOSE 5000

CMD ["python3.11", "app.py", "-c", "/etc/microcert/config/ca.crt", "-k", "/etc/microcert/config/ca.key", "-t", "/etc/microcert/config/token"]
