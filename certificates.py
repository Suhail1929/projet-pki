from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

def Gen_key(x):
    # Génère une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def Ext_Priv(x):
    # Extrait la clé privée d'une paire de clés
    return x.private_key()

def Ext_Pub(x):
    # Extrait la clé publique d'une paire de clés
    return x.public_key()

def Chif_asym(M, Kpub):
    # Chiffre un message avec une clé publique RSA
    encrypted = Kpub.encrypt(
        M,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted

def Dechif_asym(M, Kpriv):
    # Déchiffre un message avec une clé privée RSA
    decrypted = Kpriv.decrypt(
        M,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted

def Signe(M, Kpriv):
    # Signe un message avec une clé privée RSA
    signature = Kpriv.sign(
        M,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def Verifie(M, Kpub, s):
    # Vérifie la signature d'un message avec une clé publique RSA
    try:
        Kpub.verify(
            s,
            M,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False

def Chif_sym(M, K):
    # Chiffre un message avec une clé symétrique (AES)
    cipher = Cipher(algorithms.AES(K), modes.EAX())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(M) + encryptor.finalize()
    return encryptor.tag, ciphertext

def Dechif_sym(M, K, tag):
    # Déchiffre un message avec une clé symétrique (AES)
    cipher = Cipher(algorithms.AES(K), modes.EAX(tag))
    decryptor = cipher.decryptor()
    return decryptor.update(M) + decryptor.finalize()

def Envoi(S, M, D):
    # Placeholder pour la logique d'envoi de messages
    pass

def Reçois(S, M, D):
    # Placeholder pour la logique de réception de messages
    pass

def Creer_Certif(Pub, s, date, C):
    # Crée un certificat avec une clé publique et une signature de la PKI
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"CA"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        Pub
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(s, hashes.SHA256())
    return cert

def hasher(M):
    # Génère une empreinte SHA-256 pour un message
    digest = hashes.Hash(hashes.SHA256())
    digest.update(M)
    return digest.finalize()