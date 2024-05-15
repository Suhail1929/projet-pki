from cryptography import x509
from certificates import Verifie

# Charge le certificat de la CA
with open("ca_cert.pem", "rb") as f:
    ca_cert_pem = f.read()
ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

def receive_message(payload):
    # Réception du message, de la signature et du certificat
    message = payload["message"]
    signature = payload["signature"]
    cert = x509.load_pem_x509_certificate(payload["cert"])

    # Vérifie la signature du message avec la clé publique du certificat reçu
    if Verifie(message, cert.public_key(), signature):
        print("Signature valide.")
    else:
        print("Signature invalide.")

# Exemple de réception de message
payload = {
    "message": b"Hello, world!",
    "signature": b"<signature_bytes>",
    "cert": b"<certificate_bytes>"
}
receive_message(payload)
