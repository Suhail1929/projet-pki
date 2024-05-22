#-------------------------------------------------------------------------------
#   @file vendor.py
#   @author HADID Hocine, MTARFI Suhail et DESESSARD Guillaume
#   @brief Code gérant les vendeurs
#   @version 1.0
#   @date 22/05/2024
#   @compiler Python 3.11.1
#   @copyright Copyright (c) 2024
#-------------------------------------------------------------------------------

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json

'''
La classe Vendor est responsable de la gestion des certificats pour les vendeurs.
'''
class Vendor:
    def __init__(self, id, revoked=False):
        # Initialisation du vendeur avec un ID unique et un etat de révocation
        self.id = id
        # Générer une paire de clés RSA pour le vendeur
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # Initialiser le certificat à None
        self.cert = None
        # Initialiser l'état de révocation du certificat
        self.revoked = revoked

        # Configuration du client MQTT
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        # Connexion au broker MQTT
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.loop_start()

        # Demander un certificat dès que le vendeur est initialisé
        self.request_cert()

    def on_connect(self, client, userdata, flags, rc):
        # Callback appelée lors de la connexion au broker MQTT
        print(f"Vendor {self.id} connected to MQTT broker with result code {rc}")

    def request_cert(self):
        # Demander un certificat à l'autorité de certification 
        public_key_pem = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        # Préparer le message de demande de certificat
        message = {
            "type": "cert_request",
            "public_key": public_key_pem,
            "response_topic": f"vehicle/hsg/vendor{self.id}"
        }
        # S'abonner au sujet où le certtificat sera envoyé en reponse
        self.mqtt_client.subscribe(f"vehicle/hsg/vendor{self.id}")
        # Envoyer la demande de certificat à la CA
        print(f"Vendor {self.id} requesting certificate")
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(message))

    def on_message(self, client, userdata, msg):
        # Callback appelée lors de la réception d'un message MQTT
        message = json.loads(msg.payload)
        print(f"Vendor {self.id} received message: {message}")
        if message["type"] == "cert_response":
            # Si le message est une réponse contenant un certificat
            self.cert = message["cert"]
            print(f"Vendor {self.id} received certificate")
            # Si le vendeur est révoqué, révoquer le certificat
            if self.revoked:
                self.revoke_cert()

    def revoke_cert(self):
        # Demander la révocation du certificat du vendeur
        message = {
            "type": "revocation_request",
            "cert": self.cert
        }
        print(f"Vendor {self.id} sending revocation request")
        # Envoyer la demande de révocation à la CA 
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(message))


# Créationn de deux instances de vendeurs avec des états de révocation différents
vendor1 = Vendor(id=1, revoked=False)
vendor2 = Vendor(id=2, revoked=True)

# Maintenir les vendeurs en activité
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping Vendors...")
