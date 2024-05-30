#-------------------------------------------------------------------------------
#   @file generate_cert_ca.py
#   @author HADID Hocine, MTARFI Suhail et DESESSARD Guillaume
#   @brief Code permettant de générer un certificat pour l'autorité de certification (CA)
#   @version 1.0
#   @date 22/05/2024
#   @compiler Python 3.11.1
#   @copyright Copyright (c) 2024
#-------------------------------------------------------------------------------

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import datetime


# Générer la clé de l'autorité de certification (CA)
ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Générer le certificat de l'autorité de certification (CA)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, u"FR"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"IDF"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Paris"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Example CA"),
    x509.NameAttribute(NameOID.COMMON_NAME, u"example.com"),
])
ca_cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
    ca_key.public_key()
).serial_number(x509.random_serial_number()).not_valid_before(
    datetime.datetime.utcnow()
).not_valid_after(
    datetime.datetime.utcnow() + datetime.timedelta(days=365)
).add_extension(
    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
    critical=False,
).sign(ca_key, hashes.SHA256())

# Enregistrer le certificat de l'autorité de certification (CA)
with open("ca_cert.pem", "wb") as f:
    f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

# Enregistrer la clé de l'autorité de certification (CA) (facultatif, pour une utilisation future)
with open("ca_key.pem", "wb") as f:
    f.write(ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))
