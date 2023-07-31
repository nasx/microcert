# microcert

Small Python Flask application to generate TLS certificates via API.

## Description

There are a lot of options for dynamic certificate generation, most of which use the ACME protocol. These options are often non-trivial to implement. Microcert is designed for lab/development enviroments where you need access to TLS certificates quickly and easily. This project should NOT be used in production. It provides very basic static token authentication and the Certificate Authority private key must be stored unencrypted.

## Getting Started

### Creating Certificate Authority for Microcert

Microcert should use its own Certificate Authority. To start, generate a private key as follows. The key should NOT be protected with a passphrase.

```command
openssl genrsa -out ca.key 4096
```

Then generate the CA certificate.

```command
openssl req -key ca.key -new -x509 -days 7300 -sha256 -extensions v3_ca -out ca.crt
```

Follow the prompts and leave `Common Name` and `Email Address` blank.

### Generate a Static Token

For authentication, a token is passed by the caller to Microcert's API using the `Token` header. This token is just a random string. To generate one in bash, use the following command. Save the string to a file.

```command
echo $RANDOM | md5sum > /path/to/token
```

### Create Python Virtual Environment

Create a Python virtual environment for the application.

```command
python -m venv /path/to/virtual/environment
```

Activate the virtual environment.

```command
. /path/to/virtual/environment/bin/activate
```

Install required Python dependences.

```command
pip install -U -r requirements.txt
```

### Running Microcert

To run the Microcert application, pass the required `-c/--ca-crt`, `-k/--ca-key` and `-t/--token` paremeters as follows:

```command
python app.py --ca-crt /path/to/ca.crt --ca-key /path/to/ca.key --token /path/to/token
```

## Using Microcert

Microcert has a single API endpoint at the URI `/api/certificate`. It accepts a JSON object from an HTTP POST with parameters that populate certificate attributes.

The JSON object has the following schema:

```json
{
    "type": "object",
    "properties": {
        "country_name": {"type": "string"},
        "state_or_provice_name": {"type": "string"},
        "locality_name": {"type": "string"},
        "organization_name": {"type": "string"},
        "organizational_unit_name": {"type": "string"},
        "common_name": {"type": "string"}
    }
}
```

After successfully invoking the API, a JSON object is returned with the CA used to sign the new certificate and the new certificate's TLS keypair. The return object has the following schema:

```json
{
    "type": "object",
    "properties": {
        "ca.crt": {"type": "string"},
        "tls.crt": {"type": "string"},
        "tls.key": {"type": "string"}
    }
}
```

An example using curl to invoke the API is shown below:

```command
curl \
  -H "Token: <static-token>" \
  -H "Content-Type: application/json" \
  -X POST \
  -d '{"country_name":"US","state_or_provice_name":"Virginia","locality_name":"Northern Virginia","organization_name":"UC2 PKI","organizational_unit_name":"UC2 Compute Cloud","common_name":"testing.lab.uc2.io"}' \
  http://localhost:5000/api/certificate