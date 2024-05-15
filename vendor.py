from cryptography import x509
from cryptography.hazmat.primitives import serialization
from certificates import Gen_key, Signe, Creer_Certif
import datetime

# Génère une paire de clés pour le vendeur
private_key_vendor, public_key_vendor = Gen_key("vendor")

# Charge la clé privée de la CA
with open("ca_private_key.pem", "rb") as f:
    ca_private_key_pem = f.read()
ca_private_key = serialization.load_pem_private_key(ca_private_key_pem, password=None)

def request_certificate():
    # Demande de certificat du vendeur à la CA
    cert = Creer_Certif(public_key_vendor, ca_private_key, datetime.datetime.utcnow())
    return cert

message = b"embouteillage"
# Signature du message par le vendeur
signature = Signe(message, private_key_vendor)

def send_message(cert, message, signature):
    # Prépare le message, la signature et le certificat pour l'envoi
    payload = {
        "message": message,
        "signature": signature,
        "cert": cert.public_bytes(serialization.Encoding.PEM)
    }
    return payload

# Demande de certificat et préparation du message à envoyer
cert = request_certificate()
payload = send_message(cert, message, signature)
