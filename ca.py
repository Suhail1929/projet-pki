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
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from os import urandom
'''
La classe CertificateAuthority est responsable de la gestion des certificats pour les clients et les vendeurs.
Elle gère également les demandes de révocation de certificats et vérifie l'état de révocation des certificats.
'''

def decrypt_with_rsa(private_key, ciphertext):
    try:
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
    except Exception as e:
        print(f"RSA decryption failed: {e}")
        return None


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
class CertificateAuthority:
    def __init__(self):
        # # Générer une paire de clés RSA pour la CA
        # self.ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        #Récuperer la clé privée de la CA
        with open("ca_key.pem", "rb") as f:
            ca_key_pem = f.read()
        self.ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)
        
        # Générer un certificat auto-signé pour la CA
        self.ca_cert = self.generate_self_signed_cert()
        # Liste pour stocker les certificats révoqués
        self.revoked_certs = []
        
        self.list_cert_vendor = []
        self.list_cert_client = []
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
        print(f"\nCA received message")
            
        if message["type"] == "aes_key":
            # Si le message est une demande de clé AES
            encrypted_aes_key = base64.b64decode(message["key"])
            # Récupérer la clé AES chiffrée
            aes_key = decrypt_with_rsa(self.ca_key, encrypted_aes_key)
            
            if "vendor" in message:
                # Assurer que la liste est assez grande
                vendor_id = message["vendor"]
                while len(self.list_cert_vendor) <= vendor_id:
                    self.list_cert_vendor.append(None)
                
                # Ajouter ou mettre à jour l'entrée
                self.list_cert_vendor[vendor_id] = aes_key
                print(f"\nCA received AES key from Vendor {vendor_id}")


            elif "client" in message: 
                # Assurer que la liste est assez grande
                client_id = message["client"]
                while len(self.list_cert_client) <= client_id:
                    self.list_cert_client.append(None)
                
                # Ajouter ou mettre à jour l'entrée
                self.list_cert_client[client_id] = aes_key
                print(f"\nCA received AES key from Client {client_id}")

            
        elif message["type"] == "echange_suite":
            vendor_id = message["vendor"]
            if vendor_id >= len(self.list_cert_vendor) or self.list_cert_vendor[vendor_id] is None:
                print(f"No AES key found for vendor {vendor_id}")
                return

            encrypted_vendor_message = base64.b64decode(message["message"])
            print(f"\nCA received encrypted message from Vendor {vendor_id}")
            print(f"\nCA received encrypted message: {encrypted_vendor_message}")
            decrypt_message = decrypt_with_aes(self.list_cert_vendor[vendor_id], encrypted_vendor_message)
            print(f"\nCA received decrypted message: {decrypt_message}")
            
            inner_message = json.loads(decrypt_message)            
            if inner_message["type_2"] == "cert_request":
                # Si le message est une demande de certificat
                public_key_pem = base64.b64decode(inner_message["public_key"])
                public_key = serialization.load_pem_public_key(public_key_pem)           # Charger la clé publique du demandeur
                cert = self.sign_cert(public_key)
                # Signer un certificat avec la clé publique du demandeur
                cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
                # Convertir le certificat en format PEM
                response = {
                    "type_2": "cert_response",
                    "cert": cert_pem
                }
                # Convertir la réponse en JSON
                response_json = json.dumps(response).encode()
                
                # Chiffrer la réponse avec AES
                aes_key = self.list_cert_vendor[vendor_id]
                encrypted_response = encrypt_with_aes(aes_key, response_json)
                encoded_encrypted_response = base64.b64encode(encrypted_response).decode()
                
                # Préparer la réponse chiffrée
                encrypted_response_message = {
                    "type": "echange_suite",
                    "vendor": encoded_encrypted_response
                }
                
                # Préparer la réponse contenant le certificat signé
                print(f"\nCA sending encrypted certificate to {inner_message['response_topic']}")
                # Envoi de la réponse au topic spécifié dans le message
                self.mqtt_client.publish(inner_message["response_topic"], json.dumps(encrypted_response_message))
            elif inner_message["type_2"] == "revocation_request":
                # Si le message est une demande de vérification de révocation
                cert = x509.load_pem_x509_certificate(inner_message["cert"].encode())
                # Charger le certificat à révoquer
                self.revoked_certs.append(cert.serial_number)
                # Ajouter le numéro de série du certificat à la liste des certificats révoqués
                print(f"\nCA revoked certificate: {cert.serial_number}")
        elif message["type"] == "echange_suite_client":
            client_id = message["client"]
            if client_id >= len(self.list_cert_client) or self.list_cert_client[client_id] is None:
                print(f"\nNo AES key found for vendor {client_id}")
                return

            encrypted_client_message = base64.b64decode(message["message"])
            print(f"\nCA received encrypted message from Vendor {client_id}")
            print(f"\nCA received encrypted message: {encrypted_client_message}")
            decrypt_message = decrypt_with_aes(self.list_cert_client[client_id], encrypted_client_message)
            print(f"\nCA received decrypted message: {decrypt_message}")
            
            inner_message = json.loads(decrypt_message)            
            if inner_message["type_2"] == "check_revocation":
                # Si le message est une demande de vérification de révocation
                cert = x509.load_pem_x509_certificate(inner_message["cert"].encode())
                # Charger le certificat à vérifier
                is_revoked = cert.serial_number in self.revoked_certs
                # Vérifier si le certificat est révoqué
                response = {
                    "type_2": "revocation_status",
                    "is_revoked": is_revoked
                }
                response_json = json.dumps(response).encode()


                aes_key = self.list_cert_client[client_id]
                encrypted_response = encrypt_with_aes(aes_key, response_json)
                encoded_encrypted_response = base64.b64encode(encrypted_response).decode()
                
                encrypted_response_message = {
                    "type": "echange_suite",
                    "client": encoded_encrypted_response
                }
                # Préparer la réponse contenant le statut de révocation
                print(f"\nCA sending revocation status to {inner_message['response_topic']}")
                # Envoyer la réponse au topic spécifié dans le message
                self.mqtt_client.publish(inner_message["response_topic"], json.dumps(encrypted_response_message))


ca = CertificateAuthority()
print("\nCertificate Authority started ...")
print("Click Ctrl+C to stop the CA\n")
# Lancement de la CA
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping CA...")
