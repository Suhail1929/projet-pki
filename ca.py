import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import json

class CertificateAuthority:
    def __init__(self):
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ca_cert = self.generate_self_signed_cert()
        self.revoked_certs = []

        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.subscribe("vehicle/hsg/ca")
        self.mqtt_client.loop_start()

    def on_connect(self, client, userdata, flags, rc):
        print("CA connected to MQTT broker with result code " + str(rc))

    def generate_self_signed_cert(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"IDF"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            self.ca_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256())
        return cert

    def sign_cert(self, public_key):
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"IDF"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example Vendor"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"vendor.com"),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(
            self.ca_cert.subject
        ).public_key(public_key).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        ).sign(self.ca_key, hashes.SHA256())
        return cert

    def on_message(self, client, userdata, msg):
        message = json.loads(msg.payload)
        print(f"CA received message: {message}")
        if message["type"] == "cert_request":
            public_key = serialization.load_pem_public_key(message["public_key"].encode())
            cert = self.sign_cert(public_key)
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            response = {
                "type": "cert_response",
                "cert": cert_pem
            }
            print(f"CA sending certificate to {message['response_topic']}")
            self.mqtt_client.publish(message["response_topic"], json.dumps(response))
        elif message["type"] == "revocation_request":
            cert = x509.load_pem_x509_certificate(message["cert"].encode())
            self.revoked_certs.append(cert.serial_number)
            print(f"CA revoked certificate: {cert.serial_number}")
        elif message["type"] == "check_revocation":
            cert = x509.load_pem_x509_certificate(message["cert"].encode())
            is_revoked = cert.serial_number in self.revoked_certs
            response = {
                "type": "revocation_status",
                "is_revoked": is_revoked
            }
            print(f"CA sending revocation status to {message['response_topic']}")
            self.mqtt_client.publish(message["response_topic"], json.dumps(response))

ca = CertificateAuthority()

# Keep the CA running
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping CA...")
