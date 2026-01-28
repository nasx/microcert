import unittest
import os
import json
import subprocess
import shutil
import tempfile
from unittest.mock import patch

# We patch 'cluster' imports or functions to avoid needing Kubernetes in the test environment.
# This prevents the app from trying to load KUBECONFIG when imported.
with patch('cluster.get_cluster_name', return_value='test-cluster'):
    from app import app

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
        
        # We manually inject the args into the app module.
        # Since app.py parses args at the global level and loads files immediately, 
        # we must reload/override the global variables `ca_crt`, `ca_key`, `token` 
        # for the test context.
        import microcert
        import app as flask_app
        
        flask_app.ca_crt = microcert.load_certificate(self.ca_crt_path)
        flask_app.ca_key = microcert.load_private_key(self.ca_key_path)
        flask_app.token = self.token_value
        
        self.client = app.test_client()

    def tearDown(self):
        # Cleanup temporary files
        shutil.rmtree(self.test_dir)

    def test_generate_and_validate_certificate(self):
        """
        Simulate the README curl command and OpenSSL validation with SANs.
        """
        # 1. Prepare JSON payload (exactly like README example + new SANs)
        payload = {
            "country_name": "US",
            "state_or_provice_name": "Virginia",
            "locality_name": "Test Locality",
            "organization_name": "Test Org",
            "organizational_unit_name": "Test Unit",
            "common_name": "test.local",
            "subject_alt_names": ["test.local", "api.test.local", "127.0.0.1"]
        }

        # 2. POST request (Simulates curl)
        response = self.client.post(
            '/api/certificate',
            data=json.dumps(payload),
            content_type='application/json',
            headers={'Token': self.token_value}
        )

        self.assertEqual(response.status_code, 200, "API call failed")
        data = response.get_json()
        
        # 3. Save the generated cert to disk for OpenSSL validation
        cert_path = os.path.join(self.test_dir, "server.crt")
        with open(cert_path, "w") as f:
            f.write(data['tls.crt'])

        # 4. Validate with OpenSSL (Simulates README validation)
        # Command: openssl x509 -in server.crt -text -noout
        result = subprocess.check_output(
            ["openssl", "x509", "-in", cert_path, "-text", "-noout"]
        ).decode('utf-8')

        # 5. Assertions
        # Check for Subject Alternative Name extension existence
        self.assertIn("X509v3 Subject Alternative Name:", result)
        
        # Check specific SAN entries
        self.assertIn("DNS:test.local", result)
        self.assertIn("DNS:api.test.local", result)
        self.assertIn("IP Address:127.0.0.1", result)

    def test_backward_compatibility_no_san(self):
        """
        Ensure requests without 'subject_alt_names' still succeed
        and automatically add the Common Name to SANs.
        """
        # 1. Old-style payload (No subject_alt_names field)
        payload = {
            "country_name": "US",
            "state_or_provice_name": "Virginia",
            "locality_name": "OldTown",
            "organization_name": "Legacy Corp",
            "organizational_unit_name": "IT",
            "common_name": "legacy.local"
        }

        # 2. POST request
        response = self.client.post(
            '/api/certificate',
            data=json.dumps(payload),
            content_type='application/json',
            headers={'Token': self.token_value}
        )

        self.assertEqual(response.status_code, 200, "Legacy API call failed (Backward compatibility broken)")
        data = response.get_json()

        # 3. Save the generated cert
        cert_path = os.path.join(self.test_dir, "legacy.crt")
        with open(cert_path, "w") as f:
            f.write(data['tls.crt'])

        # 4. Validate with OpenSSL
        result = subprocess.check_output(
            ["openssl", "x509", "-in", cert_path, "-text", "-noout"]
        ).decode('utf-8')

        # 5. Verify CN was auto-added to SANs
        # The logic in microcert.py ensures that if SANs are missing, 
        # the Common Name is added as a DNSName.
        self.assertIn("X509v3 Subject Alternative Name:", result)
        self.assertIn("DNS:legacy.local", result)

if __name__ == '__main__':
    unittest.main()
