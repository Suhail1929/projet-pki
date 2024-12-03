#-------------------------------------------------------------------------------
#   @file vendor.py
#   @author HADID Hocine, MTARFI Suhail et DESESSARD Guillaume
#   @brief Code gérant les vendeurs
#   @version 1.0
#   @date 22/05/2024
#   @compiler Python 3.11.1
#   @copyright Copyright (c) 2024
#-------------------------------------------------------------------------------

import json
import paho.mqtt.client as mqtt

   

class Tester:
    def __init__(self, choice):
        # Configuration du client MQTT
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        # Connexion au broker MQTT
        self.mqtt_client.connect("194.57.103.203", 1883, 60)
        self.mqtt_client.loop_start()
        print("Tester connected to the broker")
        self.request_vendor_certificat(choice)

    def on_connect(self, client, userdata, flags, rc):
        print("Connecté au broker avec le code retour: " + str(rc))

    def on_message(self, client, userdata, msg):
        # Callback appelée lors de la réception d'un message MQTT
        message = json.loads(msg.payload)
        if message["type"] == "vendor_cert_tester":
            try:                
                print(f"Vendor certificate: {message['cert']}")
            except Exception as e:
                # En cas d'erreur
                print(f"Vendor failed to send the certificate: {e}")
                
    # une classe tester qui permet de demander au client ou au vendor d'envoyer leur certificat
    def request_vendor_certificat(self, vendor_id):
        # Envoyer une demande de certificat à un vendeur spécifique
        message = {
            "type": "vendor_request_tester_cert",
            "response_topic": f"vehicle/hsg/tester/vendor{vendor_id}"
        }
        
        print(f"Tester requesting certificate from vendor {vendor_id}")
        self.mqtt_client.subscribe(f"vehicle/hsg/tester/vendor{vendor_id}")
        self.mqtt_client.publish(f"vehicle/hsg/vendor{vendor_id}", json.dumps(message))


        
print("Starting tester...")
print("Click Ctrl+C to stop the tester")

print("Choose 1 or 2:\n")

print("1. Demand the vendor 1 to send his public key\n")
print("2. Demand the vendor 2 to send his public key\n")

choice = input("Enter your choice: ")

tester = Tester(choice)

# maitenir le programme en cours d'execution
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping tester...")
    tester.client.loop_stop()
    print("Tester stopped")


