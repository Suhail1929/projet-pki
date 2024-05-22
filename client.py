#-------------------------------------------------------------------------------
#   @file client.py
#   @author HADID Hocine, MTARFI Suhail et DESESSARD Guillaume
#   @brief Code gérant les clients
#   @version 1.0
#   @date 22/05/2024
#   @compiler Python 3.11.1
#   @copyright Copyright (c) 2024
#-------------------------------------------------------------------------------

import paho.mqtt.client as mqtt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import json

'''
La classe Client est responsable des différentes actionn du client.
'''
class Client:
    def __init__(self, id, ca_cert):
        # Initialisation du client avec un ID unique et le certificat de l'autorité de certification
        self.id = id
        self.ca_cert = x509.load_pem_x509_certificate(ca_cert.encode())

        # Configuration du client MQTT
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_message = self.on_message
        # Connexion au broker MQTT
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.loop_start()

    def verify_cert(self, cert_pem):
        # Verifier la validité du certificat en le comparant avec le certificat de la CA
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        self.ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        return cert

    def check_revocation(self, cert_pem):
        # Vérifier l'etat de révocation du certificat en demandant à la CA
        message = {
            "type": "check_revocation",
            "cert": cert_pem,
            "response_topic": f"vehicle/hsg/client{self.id}/revocation"
        }
        self.mqtt_client.subscribe(f"vehicle/hsg/client{self.id}/revocation")
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(message))

    def on_message(self, client, userdata, msg):
        # Callback appelée lors de la réception d'un message MQTT
        message = json.loads(msg.payload)
        if message["type"] == "vendor_cert":
            try:
                # Si le message est un certificat de vendeur
                cert = self.verify_cert(message["cert"])
                if self.id == 2 or self.id == 3:
                    # Si l'ID du client est 2 ou 3, vérifier l'état de révocation
                    self.check_revocation(message["cert"])
                else:
                    # Sinon afficher un message indiquant que le client a réussi à vérifier le certificat du vendeur
                    print(f"Client {self.id} successfully verified the vendor's certificate.")
            except Exception as e:
                # En cas d'erreur, afficher un message indiquant que le client a échoué à vérifier le certificat
                print(f"Client {self.id} failed to verify the certificate: {e}")
        elif message["type"] == "revocation_status":
            # Si le message contient le statut de révocation d'un certificat
            if message["is_revoked"]:
                # Si le certificat est révoqué, afficher un message indiquant que le client a découvert la révocation
                print(f"Client {self.id} discovered the certificate is revoked.")
            else:
                # Sinon, afficher un message indiquant que le client a vérifié que le certificat n'est pas révoqué
                print(f"Client {self.id} verified the certificate is not revoked.")

    def request_vendor_cert(self, vendor_id):
        # Envoyer une demande de certificat à un vendeur spécifique
        message = {
            "type": "vendor_request",
            "response_topic": f"vehicle/hsg/client{self.id}/vendor{vendor_id}"
        }
        self.mqtt_client.subscribe(f"vehicle/hsg/client{self.id}/vendor{vendor_id}")
        self.mqtt_client.publish(f"vehicle/hsg/vendor{vendor_id}", json.dumps(message))

# Charger le certificat de l'autorité de certification (CA) à partir d'un fichier, certificat généré avec generate_cert_ca.py
with open("ca_cert.pem", "r") as f:
    ca_cert_pem = f.read()

# Les clients demandent des certificats aux vendeurs spécifiques
client1 = Client(id=1, ca_cert=ca_cert_pem)
client2 = Client(id=2, ca_cert=ca_cert_pem)
client3 = Client(id=3, ca_cert=ca_cert_pem)

# Clients request certificates from vendors
client1.request_vendor_cert(1)
client2.request_vendor_cert(1)
client3.request_vendor_cert(2)

# Maintenir l'exécution des clients en continu
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping Clients...")
