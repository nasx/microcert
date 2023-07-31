from cryptography.hazmat.primitives import serialization
from flask import abort, Flask, jsonify, make_response, request
from gevent.pywsgi import WSGIServer
from json import dumps
from jsonschema import validate
from microcert import *
import argparse, jsonschema

app = Flask(__name__)

parser = argparse.ArgumentParser()

parser.add_argument('-c', '--ca-crt', required=True, help="Path to CA Certificate File")
parser.add_argument('-k', '--ca-key', required=True, help="Path to CA Certificate Key File")
parser.add_argument('-t', '--token', required=True, help="Path to Token File")

args = parser.parse_args()

ca_crt = load_certificate(args.ca_crt)
ca_key = load_private_key(args.ca_key)

token = open(args.token).read().replace('\n', '')

def validate_certificate_request_payload(request_json):
    certificate_schema = {
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

    try:
        validate(instance=request_json, schema=certificate_schema)
    except jsonschema.exceptions.ValidationError as err:
        print(err)
        abort(make_response(jsonify(message="Invalid JSON payload."), 400))

    return True

def validate_token():
    if token == request.headers.get('Token'):
        return True
    
    abort(make_response(jsonify(message="Unauthorized. Missing or invalid token."), 403))

@app.route("/api/version", methods=['GET'])
def version():
    if validate_token():
        return dumps({'version':0.1})

@app.route("/api/certificate", methods=['POST'])
def certificate():
    if validate_token() and validate_certificate_request_payload(request.json):
        key_pair = create_certificate(ca_crt, ca_key, request.json)

        return {
            "ca.crt": ca_crt.public_bytes(serialization.Encoding.PEM).decode(),
            "tls.crt": key_pair[1].public_bytes(serialization.Encoding.PEM).decode(),
            "tls.key": key_pair[0].private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
        }

if __name__ == '__main__':
    print("Starting server on port 5000...")
    WSGIServer(('', 5000), app).serve_forever()
