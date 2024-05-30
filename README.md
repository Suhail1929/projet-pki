# Projet : Simulation d'une Autorité de Certification (CA)

## Sujet 
### Objectifs du Projet

Le projet consiste à simuler une autorité de certification (CA) qui gère des certificats numériques et des listes de révocation de certificats (CRL). Les objectifs principaux sont :

- Délivrer des certificats à des vendeurs.
- Révoquer des certificats et gérer une CRL.
- Permettre aux clients de vérifier la validité et la révocation des certificats des vendeurs.

### Acteurs principaux du projet
1. CA 
2. Vendeur
3. Client 

### Scénario

#### Vendeur

1. Un vendeur demande un certificat à la CA.
2. La CA vérifie l'identité du vendeur, génère un certificat et l'envoie au vendeur.
3. Le vendeur utilise ce certificat pour prouver son identité aux clients.

#### Client

1. Un client se connecte au vendeur et reçoit son certificat.
2. Le client vérifie si le certificat est valide et non révoqué.
3. Scénarios spécifiques :
   - Vérifier simplement le certificat.
   - Vérifier le certificat et s'assurer qu'il n'est pas révoqué.
   - Le client découvre que le certificat du vendeur est révoqué.

## Dépendances
Avant toute chose, assurez d'avoir installé les librairies suivantes sur votre PC : 
   - cryptography
   - paho.mqtt.client

Pour ce faire, vous pouvez utiliser la commande suivante : 

```bash
pip install -r requirements.txt
```

## Utilisation

Afin de lancer cette simulation d'autorité de certification, il vous faut ouvrir trois terminals. 
Lancer dans un premier temps le script qui va générer un certificat auto-signé pour l'autorité de certification. 

```bash
py generate_ca_cert.py
```

Puis vous pouvez lancer les scripts suivants dans les différents terminaux :

### Terminal 1 : CA

Pour lancer l'autorité de certification, il vous suffit de lancer la commande suivante :

```bash
py ca.py
```

### Terminal 2 : Vendeur

Puis, vous lancer le vendeur : 

```bash
py vendor.py
```

### Terminal 3 : Client

Enfin, vous lancer le client : 

```bash
py client.py
```

Désormais, vous n'avez qu'a suivre les instructions affichées dans les différents terminaux pour simuler une autorité de certification.

Sachez que si vous choisissez le vendeur n°1, seul les clients 1 et 2 fonctionneront. Si vous choisissez le vendeur n°2, seul le client 3 fonctionnera.

## Auteur
- [Hocine HADID | @hocine280]
- [Suhail MTARFI | @Suhail1929]
- [Guillaume Desessard | @karibou12]