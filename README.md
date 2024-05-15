# Projet : Simulation d'une Autorité de Certification (CA)

## Objectifs du Projet

Le projet consiste à simuler une autorité de certification (CA) qui gère des certificats numériques et des listes de révocation de certificats (CRL). Les objectifs principaux sont :

- Délivrer des certificats à des vendeurs.
- Révoquer des certificats et gérer une CRL.
- Permettre aux clients de vérifier la validité et la révocation des certificats des vendeurs.

## Acteurs principaux du projet
1. CA 
2. Vendeur
3. Client 

## Scénario

### Vendeur

1. Un vendeur demande un certificat à la CA.
2. La CA vérifie l'identité du vendeur, génère un certificat et l'envoie au vendeur.
3. Le vendeur utilise ce certificat pour prouver son identité aux clients.

### Client

1. Un client se connecte au vendeur et reçoit son certificat.
2. Le client vérifie si le certificat est valide et non révoqué.
3. Scénarios spécifiques :
   - Vérifier simplement le certificat.
   - Vérifier le certificat et s'assurer qu'il n'est pas révoqué.
   - Le client découvre que le certificat du vendeur est révoqué.


## Auteur
- [Hocine HADID | @hocine280]
- [Suhail MTARFI | @Suhail1929]
- [Guillaume Desessard | @..]