import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import json

class Client:
    def __init__(self, id, ca_cert):
        self.id = id
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert.encode())

        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.loop_start()

    def verify_cert(self, cert_pem):
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        self.ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        return cert

    def check_revocation(self, cert_pem):
        message = {
            "type": "check_revocation",
            "cert": cert_pem,
            "response_topic": f"vehicle/hsg/client{self.id}/revocation"
        }
        self.mqtt_client.subscribe(f"vehicle/hsg/client{self.id}/revocation")
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(message))

    def on_message(self, client, userdata, msg):
        message = json.loads(msg.payload)
        if message["type"] == "vendor_cert":
            try:
                cert = self.verify_cert(message["cert"])
                if self.id == 2 or self.id == 3:
                    self.check_revocation(message["cert"])
                else:
                    print(f"Client {self.id} successfully verified the vendor's certificate.")
            except Exception as e:
                print(f"Client {self.id} failed to verify the certificate: {e}")
        elif message["type"] == "revocation_status":
            if message["is_revoked"]:
                print(f"Client {self.id} discovered the certificate is revoked.")
            else:
                print(f"Client {self.id} verified the certificate is not revoked.")

    def request_vendor_cert(self, vendor_id):
        message = {
            "type": "vendor_request",
            "response_topic": f"vehicle/hsg/client{self.id}/vendor{vendor_id}"
        }
        self.mqtt_client.subscribe(f"vehicle/hsg/client{self.id}/vendor{vendor_id}")
        self.mqtt_client.publish(f"vehicle/hsg/vendor{vendor_id}", json.dumps(message))

# Load CA certificate
with open("ca_cert.pem", "r") as f:
    ca_cert_pem = f.read()

client1 = Client(id=1, ca_cert=ca_cert_pem)
client2 = Client(id=2, ca_cert=ca_cert_pem)
client3 = Client(id=3, ca_cert=ca_cert_pem)

# Clients request certificates from vendors
client1.request_vendor_cert(1)
client2.request_vendor_cert(1)
client3.request_vendor_cert(2)

# Keep the clients running
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping Clients...")
