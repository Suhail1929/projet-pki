#-------------------------------------------------------------------------------
#   @file ca.py
#   @author HADID Hocine, MTARFI Suhail et DESESSARD Guillaume
#   @brief Code de l'autorité de certification (CA) pour la gestion des certificats
#   @version 1.0
#   @date 22/05/2024
#   @compiler Python 3.11.1
#   @copyright Copyright (c) 2024
#-------------------------------------------------------------------------------

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import json
'''
La classe CertificateAuthority est responsable de la gestion des certificats pour les clients et les vendeurs.
Elle gère également les demandes de révocation de certificats et vérifie l'état de révocation des certificats.
'''
class CertificateAuthority:
    def __init__(self):
        # Générer une paire de clés RSA pour la CA
        self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Générer un certificat auto-signé pour la CA
        self.ca_cert = self.generate_self_signed_cert()
        # Liste pour stocker les certificats révoqués
        self.revoked_certs = []

        # Configuration du client MQTT
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        # Connexion au broker MQTT et souscription au topic "vehicle/hsg/ca"
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.subscribe("vehicle/hsg/ca")
        # Démarrage de la boucle MQTT en arrière-plan
        self.mqtt_client.loop_start()

    def on_connect(self, client, userdata, flags, rc):
        # Callback appelée lors de la connexion au broker MQTT
        print("CA connected to MQTT broker with result code " + str(rc))

    def generate_self_signed_cert(self):
        # Générer un certificat auto-signé pour la CA
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
        # Signer un certificat avec la clé privée de la CA
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
        # Callback appelée lors de la réception d'un message MQTT
        message = json.loads(msg.payload)
        print(f"CA received message: {message}")
        if message["type"] == "cert_request":
            # Si le message est une demande de certificat
            public_key = serialization.load_pem_public_key(message["public_key"].encode())
            # Charger la clé publique du demandeur
            cert = self.sign_cert(public_key)
            # Signer un certificat avec la clé publique du demandeur
            cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            # Convertir le certificat en format PEM
            response = {
                "type": "cert_response",
                "cert": cert_pem
            }
            # Préparer la réponse contenant le certificat signé
            print(f"CA sending certificate to {message['response_topic']}")
            # Envoi de la réponse au topic spécifié dans le message
            self.mqtt_client.publish(message["response_topic"], json.dumps(response))
        elif message["type"] == "revocation_request":
            # Si le message est une demande de vérification de révocation
            cert = x509.load_pem_x509_certificate(message["cert"].encode())
            # Charger le certificat à révoquer
            self.revoked_certs.append(cert.serial_number)
            # Ajouter le numéro de série du certificat à la liste des certificats révoqués
            print(f"CA revoked certificate: {cert.serial_number}")
        elif message["type"] == "check_revocation":
            # Si le message est une demande de vérification de révocation
            cert = x509.load_pem_x509_certificate(message["cert"].encode())
            # Charger le certificat à vérifier
            is_revoked = cert.serial_number in self.revoked_certs
            # Vérifier si le certificat est révoqué
            response = {
                "type": "revocation_status",
                "is_revoked": is_revoked
            }
            # Préparer la réponse contenant le statut de révocation
            print(f"CA sending revocation status to {message['response_topic']}")
            # Envoyer la réponse au topic spécifié dans le message
            self.mqtt_client.publish(message["response_topic"], json.dumps(response))

ca = CertificateAuthority()

# Keep the CA running
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping CA...")
