import paho.mqtt.client as paho
import random
import threading
import queue
import rsa
import base64
from cryptography.fernet import Fernet, InvalidToken


CLIENT_ID = f"kyh-mqtt-{random.randint(0, 1000)}"
USERNAME = ""
PASSWORD = ""
BROKER = "broker.hivemq.com"
PORT = 1883

CHAT_ROOMS = {"room1": "chat/group1", "room2": "chat/group2", "room3": "chat/group3"}


class Chat:
    def __init__(self, username, room, secret):
        self.username = username
        self.room = room
        self.topic = CHAT_ROOMS[room]
        self.client = None
        self.connect_mqtt()
        self.input_queue = queue.Queue()
        # This variable is used to exit the thread when the
        # user exits the application
        self.running = True

        # my32lengthsupersecretnooneknows1

        key = base64.urlsafe_b64encode(bytes(secret, "utf-8"))
        try:
            self.fernet = Fernet(key)
        except:
            raise Exception(f"The secret-key must be 32 charecters")

    @staticmethod
    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print('Connected to Chat Server. Type "quit" to quit.')
        else:
            print(f"Error connecting to Chat Server. Error code {rc}")

    def connect_mqtt(self):
        # Create a MQTT client object.
        # Every client has an id
        self.client = paho.Client(CLIENT_ID)
        # Set username and password to connect to broker
        self.client.username_pw_set(USERNAME, PASSWORD)

        # When connection response is received from broker
        # call the function on_connect
        self.client.on_connect = self.on_connect

        # Connect to broker
        self.client.connect(BROKER, PORT)

    def on_message(self, client, userdata, message):
        msg = message.payload

        # Check if the message is encrypted
        if msg.startswith(b"gAAAAA"):
            try:
                decrypted_msg_bytes = self.fernet.decrypt(msg)
                decrypted_msg = decrypted_msg_bytes.decode("utf-8")
            except InvalidToken:
                print(msg)
        else:
            decrypted_msg = msg.decode("utf-8")

            if decrypted_msg.startswith(str(self.username)):
                return
            else:
                print(decrypted_msg)

    def init_client(self):
        # Subscribe to selected topic
        self.client.subscribe(self.topic)
        # Set the on_message callback function
        self.client.on_message = self.on_message

        def get_input():
            """
            Function used by the input thread
            :return: None
            """
            while self.running:
                # Get user input and place it in the input_queue
                self.input_queue.put(input())

        # Create input thread
        input_thread = threading.Thread(target=get_input)
        # and start it
        input_thread.start()

        # Start the paho client loop
        self.client.loop_start()

        # self.client.publish(self.topic, f"{self.username} , has joined the chat.")
        encrypted_msg = self.fernet.encrypt(
            f"{self.username} , has joined the chat.".encode()
        ).decode("utf-8")
        self.client.publish(self.topic, encrypted_msg)

    def run(self):
        self.init_client()

        while True:
            try:
                # Check if there is an input from the user
                # If not we will get a queue.Empty exception
                msg_to_send = self.input_queue.get_nowait()
                # If we reach this point we have a message

                # Check if the user wants to exit the application
                if msg_to_send.lower() == "quit":

                    """self.client.publish(
                        self.topic, f"{self.username} , has left the chatroom."
                    )"""
                    encrypted_msg = self.fernet.encrypt(
                        f"{self.username} , has left the chatroom.".encode()
                    ).decode("utf-8")
                    self.client.publish(self.topic, encrypted_msg)

                    # Indicate to the input thread that it can exit
                    self.running = False
                    break

        
                # self.client.publish(self.topic, f"{self.username} : {msg_to_send}")
                encrypted_msg = self.fernet.encrypt(
                    f"{self.username} : {msg_to_send}".encode()
                ).decode("utf-8")
                self.client.publish(self.topic, encrypted_msg)

            except queue.Empty:  # We will end up here if there was no user input
                pass  # No user input, do nothing

        # Stop the paho loop
        self.client.loop_stop()
        # The user needs to press ENTER to exit the while loop in the thread
        print("You have left the chat. Press [ENTER] to exit application.")


def main():
    # Init application. Ask for username and chat room
    username = input("Enter your username: ")
    secret = input("Enter the secret_key: ")

    print("Pick a room:")
    for room in CHAT_ROOMS:
        print(f"\t{room}")
    room = input("> ")

    chat = Chat(username, room, secret)
    chat.run()


if __name__ == "__main__":
    main()
