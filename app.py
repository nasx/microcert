from cryptography.hazmat.primitives import serialization
from flask import abort, Flask, jsonify, make_response, request, Request
from gevent.pywsgi import WSGIServer
from json import dumps, loads
from microcert import *

app = Flask(__name__)

ca_crt = load_certificate("local/ca/ca.crt")
ca_key = load_private_key("local/ca/ca.key")
token = open('local/token').read().replace('\n', '')

def validate_certificate_request_payload(request_json):
    required_keys = {
        'country_name': str,
        'state_or_provice_name': str,
        'locality_name': str,
        'organization_name': str,
        'organizational_unit_name': str,
        'common_name': str
    }
    
    if required_keys.keys() == request_json.keys():
        return True

    abort(make_response(jsonify(message="Invalid JSON payload."), 400))

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
