import time
import socket
import threading
import thread
import struct
import pysm4
from token import get_key, del_token
def str2hex(data):
    res = ''
    for i in data:
        res += hex(ord(i)).replace('0x','')
    return res

def log(strLog):
    strs = time.strftime("%Y-%m-%d %H:%M:%S")
    print strs + " -> " + strLog

def start_thread(thread_class):
    thread.start_new_thread(thread_class.run, ())


class pipethreadSend(threading.Thread):
    '''
    classdocs
    '''
    def __init__(self,source,sink,recv_thread=None):
        '''
        Constructor
        '''
        threading.Thread.__init__(self)
        self.source = source
        self.sink = sink
        self.recv_thread = recv_thread
        self.__is_runing = True
        log("New send Pipe create:%s->%s" % (self.source.getpeername(),self.sink.getpeername()))
    def run(self):
        self.source.settimeout(60)
        while True:
            try:
                data = self.source.recv(4096)
                break
            except socket.timeout:
                continue
            except Exception as e:
                log("first Send message failed")
                log(str(e))
                self._end()
                return
        if data is None:
            log("first Send message none")
            self._end()
            return
        print(str2hex(data))
        token = struct.unpack('i',data[0:4])[0]
        key = get_key(str(token))
        if key is None:
            self._end()
            return
        if self.recv_thread is not None:

            self.recv_thread.key = key
        print(len(data))
        print(str2hex(key))
        decrypt_message = pysm4.decrypt_ecb(data[4:],key)
        print('recv : ' + decrypt_message)

        # add verify here
        try:
            self.sink.send(decrypt_message)
        
        except Exception:
            self._end()
            return
            
        self.source.settimeout(60)
        while self.__is_runing:
            try:
                try:
                    data = self.source.recv(4096)
                except socket.timeout:
                    continue
                if not data: break

                get_token = struct.unpack('i',data[0:4])[0]
                if get_token != token:
                    break
                decrypt_message = pysm4.decrypt_ecb(data[4:],key)
                print('recv : ' + decrypt_message)

                # add verify here
                self.sink.send(decrypt_message)
            except Exception ,ex:
                log("redirect error:" + str(ex))
                break
        del_token(str(token))
        self._end()
    def terminate(self):
        self.__is_runing = False

    def _end(self):
        self.recv_thread.terminate()
        try:
            self.source.close()
            self.sink.close()
        except Exception:
            pass
        

class pipethreadRecv(threading.Thread):
    '''
    classdocs
    '''
    def __init__(self,source,sink,send_thread=None):
        '''
        Constructor
        '''
        threading.Thread.__init__(self)
        self.source = source
        self.sink = sink
        self.key = ''
        self.send_thread = send_thread
        self.__is_runing = True
        log("New recv Pipe create:%s->%s" % (self.source.getpeername(),self.sink.getpeername()))
    def run(self):
        self.source.settimeout(60)
        while True:
            try:
                data = self.source.recv(4096)
                break
            except socket.timeout:
                continue
            except Exception as e:
                log("first recv message failed")
                log(str(e))
                self._end()
                return
        if data is None:
            log("first recv message none")
            self._end()
            return

        # token = struct.unpack('i',data[0:4])[0]
        key = self.key
        if len(key) == 0:
            log("first key message failed")
            self._end()
            return
        encrypt_message = pysm4.encrypt_ecb(data,key)
        print('send : ' + data)
        try:
            self.sink.send(encrypt_message)
        
        except Exception:
            self._end()
            return
        self.source.settimeout(60)
        while self.__is_runing:
            try:
                try:
                    data = self.source.recv(4096)
                except socket.timeout:
                    continue
                if not data: break
                encrypt_message = pysm4.encrypt_ecb(data,key)
                print('send : ' + data)

                # add verify here
                self.sink.send(encrypt_message)
            except Exception ,ex:
                log("redirect error:" + str(ex))
                break
        self._end() 

    def terminate(self):
        self.__is_runing = False

    def _end(self):
        self.send_thread.terminate()
        try:
            self.source.close()
            self.sink.close()
        except Exception:
            pass

class portmap(threading.Thread):

    def __init__(self, port, newhost, newport, local_ip=''):
        threading.Thread.__init__(self)
        self.newhost = newhost
        self.newport = newport
        self.port = port
        self.local_ip = local_ip
        self.protocol = 'tcp'
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.sock.bind((self.local_ip, port))
        self.sock.listen(5)
        log("start listen protocol:%s,port:%d " % (self.protocol, port))

    def run(self):
        self.sock.settimeout(5)
        while True:
            try:
                newsock, address = self.sock.accept()
            except socket.timeout:
                continue
            log("new connection->protocol:%s,local port:%d,remote address:%s" % (self.protocol, self.port,address[0]))
            fwd = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            try:
                fwd.connect((self.newhost,self.newport))
            except Exception ,ex:
                log("connet newhost error:" + str(ex))
                break
            p2 = pipethreadRecv(fwd, newsock)
            p1 = pipethreadSend(newsock, fwd, p2)
            p2.send_thread = p1
            start_thread(p1)
            start_thread(p2)
            # p1.start()
            # p2.start()
            # self.sock.listen(5)
class pipethreadUDP(threading.Thread):
    def __init__(self, connection, connectionTable, table_lock):
        threading.Thread.__init__(self)
        self.connection = connection
        self.connectionTable = connectionTable
        self.table_lock = table_lock
        log('new thread for new connction')
    def run(self):
        while True:
            try:
                data,addr = self.connection['socket'].recvfrom(4096)
                #log('recv from addr"%s' % str(addr))
            except Exception, ex:
                log("recvfrom error:" + str(ex))
                break
            try:
                self.connection['lock'].acquire()
                self.connection['Serversocket'].sendto(data,self.connection['address'])
                #log('sendto address:%s' % str(self.connection['address']))
            except Exception ,ex:
                log("sendto error:" + str(ex))
                break
            finally:self.connection['lock'].release()
            self.connection['time'] = time.time()
        self.connection['socket'].close()
        log("thread exit for: %s" % str(self.connection['address']))
        self.table_lock.acquire()
        self.connectionTable.pop(self.connection['address'])
        self.table_lock.release()
        log('Release udp connection for timeout:%s' % str(self.connection['address']))
class portmapUDP(threading.Thread):
    def __init__(self, port, newhost, newport, local_ip=''):
        threading.Thread.__init__(self)
        self.newhost = newhost
        self.newport = newport
        self.port = port
        self.local_ip = local_ip
        self.sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.sock.bind((self.local_ip,port))
        self.connetcTable = {}
        self.port_lock = threading.Lock()
        self.table_lock = threading.Lock()
        self.timeout = 300
        #ScanUDP(self.connetcTable,self.table_lock).start()
        log('udp port redirect run->local_ip:%s,local_port:%d,remote_ip:%s,remote_port:%d' % (local_ip,port,newhost,newport))
    def run(self):
        while True:
            data,addr = self.sock.recvfrom(4096)
            connection = None
            newsock = None
            self.table_lock.acquire()
            connection = self.connetcTable.get(addr)
            newconn = False
            if connection is None:
                connection = {}
                connection['address'] = addr
                newsock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                newsock.settimeout(self.timeout)
                connection['socket'] = newsock
                connection['lock'] = self.port_lock
                connection['Serversocket'] = self.sock
                connection['time'] = time.time()
                newconn = True
                log('new connection:%s' % str(addr))
            self.table_lock.release()
            try:
                connection['socket'].sendto(data,(self.newhost,self.newport))
            except Exception ,ex:
                log("sendto error:" + str(ex))
                #break
            if newconn:
                self.connetcTable[addr] = connection
                t1 = pipethreadUDP(connection,self.connetcTable,self.table_lock)
                t1.start()
        log('main thread exit')
        for key in self.connetcTable.keys():
            self.connetcTable[key]['socket'].close()
if __name__ == '__main__':
    myp = portmap(12345, '127.0.0.1', 5002)
    myp.start()