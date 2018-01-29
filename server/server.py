import rsa
import socket
import struct
import pysm4
import base64

def str2hex(data):
    res = ''
    for i in data:
        res += hex(ord(i))
    return res

HOST = '127.0.0.1'
PORT = 6786

f = open('rsakey.pem')
rsakey = f.read()
f.close()

prikey = rsa.PrivateKey.load_pkcs1(rsakey)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(5)
print('Server start at: %s:%s' % (HOST, PORT))
print('wait for connection...')

while True:
    conn, addr = s.accept()
    print('Connected by ', addr)

    while True:
        data = conn.recv(1024)
        print("received: ")
        de = rsa.decrypt(data, prikey)
        print("maigc : " + str(struct.unpack('i',de[0:4])))
        print("sm4 key : " + str2hex(de[4:20]))
        print("program hash : " + str2hex(de[20:52]))
        message = struct.pack('i',0x66666666) + de[4:20] + struct.pack('i',1)
        conn.send(pysm4.encrypt_ecb(message,de[4:20]))