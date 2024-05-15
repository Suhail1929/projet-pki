import paho.mqtt.client as mqtt
import json
from client import receive_message

# Fonction appelée lors de la connexion au serveur MQTT
def on_connect(client, userdata, flags, rc):
    print("Connecté avec le code de résultat " + str(rc))
    client.subscribe("vehicule")

# Fonction appelée lors de la réception d'un message MQTT
def on_message(client, userdata, msg):
    payload = json.loads(msg.payload)
    receive_message(payload)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# Connexion au serveur MQTT
client.connect("194.57.103.203", 1883, 60)
client.loop_forever()
