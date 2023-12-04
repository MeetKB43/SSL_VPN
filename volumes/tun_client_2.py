#!/usr/bin/python3
import os
os.system("pip install pycryptodome")
import json
import fcntl
import struct
import os
import time
from scapy.all import *
from select import select
from AES import AESCipher
import random
import hashlib
import base64

#prime num
p = 6668014432879854274079851790721257797144758322315908160396257811764037237817632071521432200871554290742929910593433240445888801654119365080363356052330830046095157579514014558463078285911814024728965016135886601981690748037476461291162945139
TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
client_pass = "client_2_welcome"
client_secret = random.getrandbits(128)

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.52.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("route add -net 192.168.60.0/24 {}".format(ifname))

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serverIP="10.0.2.5"
serverPort=3000

# Connect to the TCP server
sock.connect((serverIP, serverPort))
print("Connected to TCP server")

def string_to_int(s, modulo):
    return int(hashlib.sha256(s.encode()).hexdigest(), 16) % modulo
def int_to_hex_string(num):
    return hex(num)[2:]
def hash_message_with_password(message, password, algorithm='sha256'):
    # Concatenate the message and password
    data = message + password.encode('utf-8')

    # Hash the concatenated data using the specified algorithm
    hashed = hashlib.new(algorithm, data).digest()

    # Return the hashed message as a base64-encoded string
    return base64.b64encode(hashed).decode('utf-8')

#deffie helman key exchange
g = string_to_int(client_pass, p)
client_public = pow(g,client_secret, p)
data = json.dumps({"client_public":client_public}, indent=2).encode('utf-8')
sock.send(data)
data = sock.recv(2048)
raw_data = json.loads(data.decode('utf-8'))
server_public = raw_data["server_public"]
sk = pow(server_public, client_secret, p)
sk = int_to_hex_string(sk)
print("Shared secret:", sk)
print("\n")

while True:   
   # this will block until at least one interface is ready
   ready, _, _ = select([sock, tun], [], [])
   AESObj = AESCipher(sk)
   for fd in ready:
      if fd is tun:
         packet = os.read(tun, 2048)
         hashed_message = hash_message_with_password(packet, client_pass)
         msg = {
            "data": base64.b64encode(packet).decode('utf-8'),
            "hash": hashed_message
         }
         encrypted_packet = AESObj.encrypt(json.dumps(msg).encode('utf-8'))
         
         sock.send(encrypted_packet)
      if fd is sock:
         data = sock.recv(2048)
         if not data:
            break
         decrypted_data = AESObj.decrypt(data)
         data = json.loads(decrypted_data.decode('utf-8'))
         packet = data["data"]
         packet = base64.b64decode(packet.encode('utf-8'))
         hashed_message = hash_message_with_password(packet, client_pass)
         if not hashed_message == data["hash"]:
            break
         os.write(tun, packet)