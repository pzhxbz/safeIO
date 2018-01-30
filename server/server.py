import rsa
import socket
import struct
import pysm4
import base64
import thread
from token import add_key
from portforward import portmap


CLIENT_HELLO_MAGIC = 0x23333333

VERIFY_SUCESS = 1
TOKEN_FULL = 2


def str2hex(data):
    res = ''
    for i in data:
        res += hex(ord(i)).replace('0x','')
    return res

def start_portforward():
    portforward = portmap(9999,"127.0.0.1",6787)
    portforward.run()

HOST = '127.0.0.1'
PORT = 6786

f = open('rsakey.pem')
rsakey = f.read()
f.close()

prikey = rsa.PrivateKey.load_pkcs1(rsakey)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))


# threading.Thread(target=start_portforward).run()
thread.start_new_thread(start_portforward, ())

def verify_client(conn, addr):
    data = conn.recv(1024)
    print("received: ")
    de = rsa.decrypt(data, prikey)
        
    recv_magic = struct.unpack('i',de[0:4])[0]
        
    print("maigc : " + str(recv_magic))
    if recv_magic != CLIENT_HELLO_MAGIC:
        print('magic verify failed!')
        conn.close()
        return
    recv_key = de[4:20]
    print("sm4 key : " + str2hex(recv_key))

    print("program hash : " + str2hex(de[20:52]))

    send_token = add_key(recv_key)
        
    if send_token is None:
        message = struct.pack('i',0x66666666) + de[4:20] + struct.pack('i',TOKEN_FULL)
    else:
        message = struct.pack('i',0x66666666) + de[4:20] + struct.pack('i',VERIFY_SUCESS) + struct.pack('i',send_token)
        print(send_token)
    conn.send(pysm4.encrypt_ecb(message,de[4:20]))
    conn.close()

print('Server start at: %s:%s' % (HOST, PORT))
print('wait for connection...')
s.settimeout(5)
while True:
    s.listen(5)
    try:
        conn, addr = s.accept()
    except socket.timeout:
        continue
    print('Connected by ', addr)
    
    #threading.Thread(target=verify_client, args=(conn,addr,)).start()
    thread.start_new_thread(verify_client,(conn,addr,))