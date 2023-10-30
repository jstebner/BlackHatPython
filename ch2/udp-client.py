import socket

target_host = "127.0.0.1"
target_port = 9997

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# BIND CLIENT TO PORT BC BOOK DIDNT DO IT LIKE WTF
client.bind((target_host, target_port))

# send some data
client.sendto(b"AAABBBCCC", (target_host, target_port))

# receive some data
data, addr = client.recvfrom(4096)

print(data.decode())
client.close()
