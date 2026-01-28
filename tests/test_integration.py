import unittest
import os
import json
import subprocess
import shutil
import tempfile
import sys
from unittest.mock import patch, MagicMock

# --- CRITICAL FIX START ---
# 1. Create a real temporary file for the token to satisfy app.py's import
#    This avoids mocking 'open' globally, which breaks prometheus_client
init_token_file = tempfile.NamedTemporaryFile(delete=False, mode='w')
init_token_file.write("dummy_token_value_for_import")
init_token_file.close()

# 2. Patch sys.argv to point to this real file
#    We still mock load_certificate/key to avoid needing valid certs during import
with patch('sys.argv', ['app.py', '-c', 'dummy.crt', '-k', 'dummy.key', '-t', init_token_file.name]), \
     patch('microcert.load_certificate', return_value=MagicMock()), \
     patch('microcert.load_private_key', return_value=MagicMock()), \
     patch('cluster.get_cluster_name', return_value='test-cluster'):
    from app import app

# 3. Clean up the temp file now that import is done
os.unlink(init_token_file.name)
# --- CRITICAL FIX END ---

class TestMicrocertIntegration(unittest.TestCase):
    def setUp(self):
        # 1. Create a temporary directory for CA files and tokens
        self.test_dir = tempfile.mkdtemp()
        self.ca_key_path = os.path.join(self.test_dir, "ca.key")
        self.ca_crt_path = os.path.join(self.test_dir, "ca.crt")
        self.token_path = os.path.join(self.test_dir, "token")
        self.token_value = "test-secret-token"

        # 2. Generate CA Key (match README: openssl genrsa)
        subprocess.check_call([
            "openssl", "genrsa", "-out", self.ca_key_path, "2048"
        ], stderr=subprocess.DEVNULL)

        # 3. Generate CA Cert (match README: openssl req)
        subprocess.check_call([
            "openssl", "req", "-key", self.ca_key_path, "-new", "-x509", 
            "-days", "1", "-sha256", "-subj", "/CN=Test CA", "-out", self.ca_crt_path
        ], stderr=subprocess.DEVNULL)

        # 4. Create Token File
        with open(self.token_path, "w") as f:
            f.write(self.token_value)

        # 5. Configure the Flask App with these paths
        app.config['TESTING'] = True
        
        # We manually inject the REAL test objects into the app module.
        # This overwrites the "dummy" mocks we used during the import.
        import microcert
        import app as flask_app
        
        flask_app.ca_crt = microcert.load_certificate(self.ca_crt_path)
        flask_app.ca_key = microcert.load_private_key(self.ca_key_path)
        flask_app.token = self.token_value
        
        self.client = app.test_client()

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    def test_generate_and_validate_certificate(self):
        """
        Simulate the README curl command and OpenSSL validation with SANs.
        """
        payload = {
            "country_name": "US",
            "state_or_provice_name": "Virginia",
            "locality_name": "Test Locality",
            "organization_name": "Test Org",
            "organizational_unit_name": "Test Unit",
            "common_name": "test.local",
            "subject_alt_names": ["test.local", "api.test.local", "127.0.0.1"]
        }

        response = self.client.post(
            '/api/certificate',
            data=json.dumps(payload),
            content_type='application/json',
            headers={'Token': self.token_value}
        )

        self.assertEqual(response.status_code, 200, f"API call failed: {response.data}")
        data = response.get_json()
        
        cert_path = os.path.join(self.test_dir, "server.crt")
        with open(cert_path, "w") as f:
            f.write(data['tls.crt'])

        # Validate with OpenSSL
        result = subprocess.check_output(
            ["openssl", "x509", "-in", cert_path, "-text", "-noout"]
        ).decode('utf-8')

        self.assertIn("X509v3 Subject Alternative Name:", result)
        self.assertIn("DNS:test.local", result)
        self.assertIn("IP Address:127.0.0.1", result)

    def test_backward_compatibility_no_san(self):
        """
        Ensure requests without 'subject_alt_names' still succeed.
        """
        payload = {
            "country_name": "US",
            "state_or_provice_name": "Virginia",
            "locality_name": "OldTown",
            "organization_name": "Legacy Corp",
            "organizational_unit_name": "IT",
            "common_name": "legacy.local"
        }

        response = self.client.post(
            '/api/certificate',
            data=json.dumps(payload),
            content_type='application/json',
            headers={'Token': self.token_value}
        )

        self.assertEqual(response.status_code, 200, f"Legacy API call failed: {response.data}")
        data = response.get_json()

        cert_path = os.path.join(self.test_dir, "legacy.crt")
        with open(cert_path, "w") as f:
            f.write(data['tls.crt'])

        result = subprocess.check_output(
            ["openssl", "x509", "-in", cert_path, "-text", "-noout"]
        ).decode('utf-8')

        self.assertIn("X509v3 Subject Alternative Name:", result)
        self.assertIn("DNS:legacy.local", result)

if __name__ == '__main__':
    unittest.main()