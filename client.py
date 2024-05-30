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
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
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
La classe Client est responsable des différentes actionn du client.
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
        
        self.aes_key = generate_aes_key()
        self.public_key_ca = load_public_key_ca()
        self.encrypted_aes_key = encrypt_with_rsa(self.public_key_ca, self.aes_key)

        encoded_message = encode_for_transport(self.encrypted_aes_key)
        print(f"Client {self.id} sending AES key to CA")
        message = json.dumps({"type": "aes_key", "client":self.id, "key": encoded_message.decode()})
        self.mqtt_client.publish("vehicle/hsg/ca", message)  
        
        if(self.id == 1): 
            print(f"Client {self.id} sending AES key to Vendor 1")
            message = json.dumps({"type": "aes_key", "key": encoded_message.decode()})
            self.mqtt_client.publish("vehicle/hsg/vendor1", message)  
        elif(self.id == 2):
            print(f"Client {self.id} sending AES key to Vendor 1")
            message = json.dumps({"type": "aes_key", "key": encoded_message.decode()})
            self.mqtt_client.publish("vehicle/hsg/vendor1", message)
        elif(self.id == 3):
            print(f"Client {self.id} sending AES key to Vendor 2")
            message = json.dumps({"type": "aes_key", "key": encoded_message.decode()})
            self.mqtt_client.publish("vehicle/hsg/vendor2", message)

    def verify_cert(self, cert_pem):
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        public_key = self.ca_cert.public_key()
        # Le contenu original du certificat (tbs_certificate_bytes) et la signature à vérifier
        original_data = cert.tbs_certificate_bytes
        signature = cert.signature
        
        # Vérification de la signature
        try:
            public_key.verify(
                signature,
                original_data,
                padding.PKCS1v15(),  # Spécification du padding utilisé pour la signature
                cert.signature_hash_algorithm  # Utilisation de l'algorithme de hashage tel que défini dans le certificat
            )
            print(f"Client {self.id}: Certificate verified successfully.")
        except Exception as e:
            print(f"Client {self.id} failed to verify the certificate: {e}")
            raise

        return cert


    def check_revocation(self, cert_pem):
        # Vérifier l'etat de révocation du certificat en demandant à la CA
        message = {
            "type_2": "check_revocation",
            "cert": cert_pem,
            "response_topic": f"vehicle/hsg/client{self.id}/revocation"
        }
        
        # Convertir le message en JSON
        message_json = json.dumps(message).encode()
        
        # Chiffrer le message avec AES
        encrypted_message = encrypt_with_aes(self.aes_key, message_json)
        encoded_encrypted_message = base64.b64encode(encrypted_message).decode()
        
        # Préparer le message chiffré
        encrypted_message_to_send = {
            "type": "echange_suite_client",
            "client": self.id,
            "message": encoded_encrypted_message
        }
        
        self.mqtt_client.subscribe(f"vehicle/hsg/client{self.id}/revocation")
        self.mqtt_client.publish("vehicle/hsg/ca", json.dumps(encrypted_message_to_send))

    def on_message(self, client, userdata, msg):
        # Callback appelée lors de la réception d'un message MQTT
        message = json.loads(msg.payload)
        if message["type"] == "echange_suite":
            encrypted_message = base64.b64decode(message["client"])
            decrypted_message = decrypt_with_aes(self.aes_key, encrypted_message)
            inner_message = json.loads(decrypted_message)
            if inner_message["type_2"] == "revocation_status":
                # Si le message contient le statut de révocation d'un certificat
                if inner_message["is_revoked"]:
                    # Si le certificat est révoqué, afficher un message indiquant que le client a découvert la révocation
                    print(f"Client {self.id} discovered the certificate is revoked.")
                else:
                    # Sinon, afficher un message indiquant que le client a vérifié que le certificat n'est pas révoqué
                    print(f"Client {self.id} verified the certificate is not revoked.")
        if message["type"] == "vendor_cert":
            try:                
                if self.id == 2 or self.id == 3:
                    # Si l'ID du client est 2 ou 3, vérifier l'état de révocation
                    self.check_revocation(message["cert"])
                    print(f"Client {self.id} verified the vendor's certificate and requested revocation status.")
                else:
                    # Sinon afficher un message indiquant que le client a réussi à vérifier le certificat du vendeur
                    print(f"Client {self.id} successfully verified the vendor's certificate.")
            except Exception as e:
                # En cas d'erreur, afficher un message indiquant que le client a échoué à vérifier le certificat
                print(f"Client {self.id} failed to verify the certificate: {e}")

    def request_vendor_cert(self, vendor_id):
        # Envoyer une demande de certificat à un vendeur spécifique
        message = {
            "type": "vendor_request",
            "response_topic": f"vehicle/hsg/client{self.id}/vendor{vendor_id}"
        }
        
        print(f"Client {self.id} requesting certificate from vendor {vendor_id}")
        self.mqtt_client.subscribe(f"vehicle/hsg/client{self.id}/vendor{vendor_id}")
        self.mqtt_client.publish(f"vehicle/hsg/vendor{vendor_id}", json.dumps(message))

# Charger le certificat de l'autorité de certification (CA) à partir d'un fichier, certificat généré avec generate_cert_ca.py
with open("ca_cert.pem", "r") as f:
    ca_cert_pem = f.read()

print("\nClient started ...")
print("Click Ctrl+C to stop the CA\n")

print("Choose the client ID (1, 2 or 3):\n")
print("1. Client 1, you need to start a Vendor 1. This scenario only checks the certificate")
print("2. Client 2, you need to start a Vendor 1. This scenario checks the certificate and revocation status")
print("3. Client 3, you need to start a Vendor 2. This scenario checks the certificate and the revocation status. In this case, the certificate is revoked")

choice = input("\nEnter the client ID: ")

if choice == "1":
    client1 = Client(id=1, ca_cert=ca_cert_pem)
    client1.request_vendor_cert(1)
elif choice == "2":
    client2 = Client(id=2, ca_cert=ca_cert_pem)
    client2.request_vendor_cert(1)
elif choice == "3":
    client3 = Client(id=3, ca_cert=ca_cert_pem)
    client3.request_vendor_cert(2)

# Maintenir l'exécution des clients en continu
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping Clients...")
