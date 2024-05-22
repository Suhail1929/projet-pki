import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json

class Vendor:
    def __init__(self, id, revoked=False):
        self.id = id
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert = None
        self.revoked = revoked

        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.loop_start()

        self.request_cert()

    def on_connect(self, client, userdata, flags, rc):
        print(f"Vendor {self.id} connected to MQTT broker with result code {rc}")

    def request_cert(self):
        public_key_pem = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        message = {
            "type": "cert_request",
            "public_key": public_key_pem,
            "response_topic": f"vehicle/hsg/vendor{self.id}"
        }
        self.mqtt_client.subscribe(f"vehicle/hsg/vendor{self.id}")
        print(f"Vendor {self.id} requesting certificate")
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(message))

    def on_message(self, client, userdata, msg):
        message = json.loads(msg.payload)
        print(f"Vendor {self.id} received message: {message}")
        if message["type"] == "cert_response":
            self.cert = message["cert"]
            print(f"Vendor {self.id} received certificate")
            if self.revoked:
                self.revoke_cert()

    def revoke_cert(self):
        message = {
            "type": "revocation_request",
            "cert": self.cert
        }
        print(f"Vendor {self.id} sending revocation request")
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(message))

vendor1 = Vendor(id=1, revoked=False)
vendor2 = Vendor(id=2, revoked=True)

# Keep the vendors running
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping Vendors...")
