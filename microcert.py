from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import Certificate
from cryptography.x509.oid import NameOID
import datetime
import ipaddress

def load_certificate(crt_file):
    data = open(crt_file, 'rb').read()
    return x509.load_pem_x509_certificate(data)

def load_private_key(key_file):
    data = open(key_file, 'rb').read()
    return load_pem_private_key(data, None)

def create_certificate(ca_crt: Certificate, ca_key: Certificate, request_json):
    now = datetime.datetime.now(datetime.UTC)
    new_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    # --- Backward Compatibility Logic ---
    # 1. Fetch SANs if present, otherwise default to empty list.
    alt_names_raw = request_json.get('subject_alt_names', [])
    
    # 2. Always include Common Name in SANs (modern standard), 
    # but avoid duplication if the user already provided it in the SAN list.
    cn = request_json.get('common_name')
    if cn and cn not in alt_names_raw:
        alt_names_raw.append(cn)

    san_items = []
    for name in alt_names_raw:
        try:
            # 3. auto-detect IP vs DNS to prevent crashes
            ip_obj = ipaddress.ip_address(name)
            san_items.append(x509.IPAddress(ip_obj))
        except ValueError:
            san_items.append(x509.DNSName(name))
    
    # 4. Build the extension object only if we have items (we almost always will due to CN)
    san_extension = x509.SubjectAlternativeName(san_items)
    # -------------------------------------

    builder = x509.CertificateBuilder(
        issuer_name=ca_crt.issuer,
        not_valid_after=(now + datetime.timedelta(days=365)),
        not_valid_before=now,
        public_key=new_key.public_key(),
        serial_number=x509.random_serial_number(),
        subject_name=x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, request_json['country_name']),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, request_json['state_or_provice_name']),
            x509.NameAttribute(NameOID.LOCALITY_NAME, request_json['locality_name']),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, request_json['organization_name']),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, request_json['organizational_unit_name']),
            x509.NameAttribute(NameOID.COMMON_NAME, request_json['common_name'])
        ])
    )

    # Apply extension
    if san_items:
        builder = builder.add_extension(san_extension, critical=False)

    return new_key, builder.sign(
        ca_key,
        hashes.SHA256(),
        default_backend()
    )
