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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
import base64
from os import urandom

'''
La classe Vendor est responsable de la gestion des certificats pour les vendeurs.
'''

def generate_aes_key(): 
    # Générer une clé AES 256 pour le chiffrement des messages
    key = urandom(32)
    return key

def encrypt_with_rsa(public_key, message):
    # Chiffrement RSA de la clé AES avec la clé publique RSA de la CA
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def encrypt_with_aes(key, plaintext):
    # Chiffrer avec AES
    iv = urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(plaintext) + encryptor.finalize()

def decrypt_with_aes(key, ciphertext):
    iv, ct = ciphertext[:16], ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def load_public_key_ca(): 
    with open("ca_cert.pem", "rb") as f:
        ca_cert_pem = f.read()
        
    # Charger le certificat à partir du PEM
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

    # Extraire la clé publique du certificat
    public_key = ca_cert.public_key()
    
    return public_key

def encode_for_transport(ciphertext):
    return base64.b64encode(ciphertext)
    
def decrypt_with_rsa(private_key, ciphertext):
    # Déchiffrement RSA de la clé AES
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext
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

        with open("ca_key.pem", "rb") as f:
            ca_key_pem = f.read()
        self.key_private = serialization.load_pem_private_key(ca_key_pem, password=None)

        # Configuration du client MQTT
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        # Connexion au broker MQTT
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.loop_start()
        
        self.list_cert_client = []
        
        self.aes_key = generate_aes_key()
        self.public_key_ca = load_public_key_ca()
        self.encrypted_aes_key = encrypt_with_rsa(self.public_key_ca, self.aes_key)

        encoded_message = encode_for_transport(self.encrypted_aes_key)
        print(f"Vendor {self.id} sending AES key to CA : {self.aes_key}")
        message = json.dumps({"type": "aes_key", "vendor" : self.id, "key": encoded_message.decode()})
        self.mqtt_client.publish("vehicle/hsg/ca", message)       
        
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
        )
        # Encoder la clé publique en base64
        public_key_b64 = base64.b64encode(public_key_pem).decode()

        # Préparer le message de demande de certificat
        message = {
            "type_2": "cert_request",
            "public_key": public_key_b64,
            "response_topic": f"vehicle/hsg/vendor{self.id}"
        }
        
        print("Contenu de l'envoi : ", message)
        
        # Chiffrement des messages avec AES
        encrypted_message = encrypt_with_aes(self.aes_key, json.dumps(message).encode())
        encoded_message = encode_for_transport(encrypted_message)

        # S'abonner au sujet où le certificat sera envoyé en reponse
        self.mqtt_client.subscribe(f"vehicle/hsg/vendor{self.id}")
        # Envoyer la demande de certificat à la CA
        print(f"Vendor {self.id} requesting certificate")
        message_to_send = json.dumps({"type": "echange_suite", "vendor": self.id, "message" : encoded_message.decode()})
        self.mqtt_client.publish("vehicle/hsg/ca", message_to_send)

    def on_message(self, client, userdata, msg):
        # Callback appelée lors de la réception d'un message MQTT
        message = json.loads(msg.payload)
               
        if message["type"] == "aes_key":
            # Si le message est une demande de clé AES
            encrypted_aes_key = base64.b64decode(message["key"])
            # Récupérer la clé AES chiffrée
            aes_key = decrypt_with_rsa(self.key_private, encrypted_aes_key)
            
            if "vendor" in message:
                # Assurer que la liste est assez grande
                vendor_id = message["vendor"]
                while len(self.list_cert_vendor) <= vendor_id:
                    self.list_cert_vendor.append(None)
                
                # Ajouter ou mettre à jour l'entrée
                self.list_cert_vendor[vendor_id] = aes_key
            elif "client" in message: 
                # Assurer que la liste est assez grande
                client_id = message["client"]
                while len(self.list_cert_client) <= client_id:
                    self.list_cert_client.append(None)
                
                # Ajouter ou mettre à jour l'entrée
                self.list_cert_client[client_id] = aes_key
            
            # Déchiffrer la clé AES avec la clé privée de la CA
            print(f"CA received AES key")
        
        if message["type"] == "echange_suite":
            encrypted_message = base64.b64decode(message["vendor"])
            decrypted_message = decrypt_with_aes(self.aes_key, encrypted_message)
            inner_message = json.loads(decrypted_message)

            if inner_message["type_2"] == "cert_response":
                # Si le message est une réponse contenant un certificat
                self.cert = inner_message["cert"]
                print(f"Vendor {self.id} received certificate")
                # Si le vendeur est révoqué, révoquer le certificat
                if self.revoked:
                    self.revoke_cert()
        if message["type"] == "vendor_request":
            # Si le message est une demande de certificat de vendeur
            print(f"Vendor {self.id} received client request")
            # Répondre avec le certificat du vendeur
            response = {
                "type": "vendor_cert",
                "cert": self.cert
            }
            self.mqtt_client.publish(message["response_topic"], json.dumps(response))
            
        if message["type"] == "vendor_request_tester_cert":
            # Si le message est une demande de certificat de vendeur
            print(f"Vendor {self.id} received client request")
            # Répondre avec le certificat du vendeur
            response = {
                "type": "vendor_cert_tester",
                "cert": self.cert
            }
            self.mqtt_client.publish(message["response_topic"], json.dumps(response))


    def revoke_cert(self):
        # Demander la révocation du certificat du vendeur
        message = {
            "type_2": "revocation_request",
            "cert": self.cert
        }
        print(f"Vendor {self.id} sending revocation request")

        # Convertir le message en JSON
        message_json = json.dumps(message).encode()

        # Chiffrer le message avec AES
        encrypted_message = encrypt_with_aes(self.aes_key, message_json)
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode()

        # Préparer le message chiffré
        encrypted_message_to_send = {
            "type": "echange_suite",
            "vendor": self.id,
            "message": encoded_encrypted_message
        }

        # Envoyer la demande de révocation à la CA
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(encrypted_message_to_send))

print("Starting Vendors...")
print("Click Ctrl+C to stop the CA\n")
print("Choose the vendor ID (1 or 2):\n")

print("1. Vendor 1 (not revoked), if you opt for this one, you must take customer 1 or 2")
print("2. Vendor 2 (revoked), if you opt for this one, you must take customer 3\n")

vendor_id = int(input("Enter the vendor ID: "))

if vendor_id == 1:
    vendor1 = Vendor(id=1, revoked=False)
elif vendor_id == 2:
    vendor2 = Vendor(id=2, revoked=True)           


# Maintenir les vendeurs en activité
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping Vendors...")
