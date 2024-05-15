from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import Encoding
import datetime
from certificates import Gen_key, Creer_Certif

# La CA génère sa propre paire de clés
ca_private_key, ca_public_key = Gen_key("ca")
# La CA crée son propre certificat auto-signé
ca_cert = Creer_Certif(ca_public_key, ca_private_key, datetime.datetime.utcnow(), "CA")

def sign_csr(csr):
    # La CA signe une CSR (Certificate Signing Request) pour émettre un certificat
    public_key = csr.public_key()
    cert = Creer_Certif(public_key, ca_private_key, datetime.datetime.utcnow())
    return cert

def verify_cert(cert):
    # La CA vérifie un certificat en utilisant sa clé publique
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return True
    except:
        return False

# Sauvegarde du certificat de la CA dans un fichier PEM
with open("ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(Encoding.PEM))
