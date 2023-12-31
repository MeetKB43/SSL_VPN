#!/usr/bin/python3
import os
os.system("pip install pycryptodome")
import json
import fcntl
import struct
import time
from scapy.all import *
from select import select
from _thread import *
from AES import AESCipher
import mysql.connector
import random
import hashlib
import base64
import threading

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
p = 6668014432879854274079851790721257797144758322315908160396257811764037237817632071521432200871554290742929910593433240445888801654119365080363356052330830046095157579514014558463078285911814024728965016135886601981690748037476461291162945139
server_secret = random.getrandbits(128)
sk = {}
usr_pass = {}
user_credentials ={
    "Meet":"Meet_234",
    "Arjun":"1kheni",
    "Rahul":"rah098"
}

#database connectivity
mydb = mysql.connector.connect(
   host="192.168.60.10",
   user="vpn_server",
   password="vpn_pass",
   database="mysql",
   port="3306"
)

mycursor = mydb.cursor()

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))
os.system("route add -net 192.168.52.0/24 {}".format(ifname))

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.bind(("0.0.0.0", 3000))
sock.listen(5) #Listen to incoming TCP requests

connected_clients = []

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


def multi_threaded_client(clientSock,IP):
    #deffie helman key exchange
    sql_query = "SELECT Password FROM Users WHERE IP = %s"
    mycursor.execute(sql_query, (IP[0],))
    local = threading.local()
    local.IPaddr = IP[0]
    usr_pass[getattr(local, 'IPaddr', None)] = (mycursor.fetchall())[0][0]
    
    g = string_to_int(usr_pass[getattr(local, 'IPaddr', None)], p)
    server_public = pow(g, server_secret, p)
    data = clientSock.recv(2048)
    raw_data = json.loads(data.decode('utf-8'))
    client_public = raw_data["client_public"]
    data = json.dumps({"server_public":server_public}, indent=2).encode('utf-8')
    clientSock.send(data)
    skTemp = pow(client_public, server_secret, p)
    sk[getattr(local, 'IPaddr', None)] = int_to_hex_string(skTemp)
    

    while True:
        # this will block until at least one interface is ready
        ready, _, _ = select([sys.stdin, clientSock, tun], [], [])
        AESObj = AESCipher(sk[getattr(local, 'IPaddr', None)])
        for fd in ready:
            if fd is sys.stdin:
                # Read input from the keyboard
                server_input = input()
                packet = {
                    "route":"chat",
                    "msg":server_input
                }
                packet = json.dumps(packet).encode('utf-8')
                # Encrypt the input message with AES
                msg = {
                    "data": base64.b64encode(packet).decode('utf-8'),
                    "hash": hash_message_with_password(packet, usr_pass[getattr(local, 'IPaddr', None)])
                }
                encrypted_packet, iv = AESObj.encrypt(json.dumps(msg).encode('utf-8'))

                # Send both encrypted packet and IV to all connected clients
                clientSock.sendall(encrypted_packet + b'|iv:' + iv)

            if fd is clientSock:
                data = clientSock.recv(4096)
                
                if not data:
                    break
                data, iv = data.split(b'|iv:',1)
                decrypted_data = AESObj.decrypt(data, iv)
                data = json.loads(decrypted_data.decode('utf-8'))
                # If no method is specified, process the packet as usual
                packet = data["data"]
                packet = base64.b64decode(packet.encode('utf-8'))
                hashed_message = hash_message_with_password(packet, usr_pass[getattr(local, 'IPaddr', None)])
                if not hashed_message == data["hash"]:
                    break
                
                try:
                    decoded_packet = packet.decode('utf-8')
                    decoded_packet = json.loads(decoded_packet)
                    if decoded_packet['route'] == "chat":
                        print("Msg from ",getattr(local, 'IPaddr', None), ": ", decoded_packet['msg'])
                    elif decoded_packet['route'] == "login":
                        reply = False
                        if decoded_packet['username'] in user_credentials:
                            if decoded_packet['password'] == user_credentials[decoded_packet['username']]:
                                reply = True
                        packet = {
                            "route":"login",
                            "msg":reply
                        }
                        packet = json.dumps(packet).encode('utf-8')
                        # Encrypt the input message with AES
                        msg = {
                            "data": base64.b64encode(packet).decode('utf-8'),
                            "hash": hash_message_with_password(packet, usr_pass[getattr(local, 'IPaddr', None)])
                        }
                        encrypted_packet, iv = AESObj.encrypt(json.dumps(msg).encode('utf-8'))

                        # Send both encrypted packet and IV to all connected clients
                        clientSock.sendall(encrypted_packet + b'|iv:' + iv)

                except:
                    os.write(tun, packet)
                

            if fd is tun:
                packet = os.read(tun, 4096)
                
                # Encrypt the HTML content with AES
                msg = {
                    "data": base64.b64encode(packet).decode('utf-8'),
                    "hash": hash_message_with_password(packet, usr_pass[getattr(local, 'IPaddr', None)])
                }
                encrypted_packet, iv = AESObj.encrypt(json.dumps(msg).encode('utf-8'))
                
                # Send both encrypted packet and IV to the client
                clientSock.sendall(encrypted_packet + b'|iv:' + iv)
        
while True:
    client_sock, addr = sock.accept()
    print("New TCP connection established: ",addr[0])
    connected_clients.append(client_sock)
    start_new_thread(multi_threaded_client, (client_sock, addr, ))