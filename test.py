import socket
from tls import TLSTester

tlsHandler = TLSTester(proto="tls13", servername = "www.google.de")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("www.google.de", 443))
#s.connect(("127.0.0.1",4433))

data = tlsHandler.handleFromRemote(None)
s.send(data)

remain = b""
s.setblocking(True)
while True:
    try:
        r = s.recv(1024)
    except BlockingIOError:
        r = b""
    if len(r) == 0:
        break
    s.setblocking(False)
    remain += r
s.setblocking(True)

data = tlsHandler.handleFromRemote(remain)

print(tlsHandler.selectedVersion)
print(tlsHandler.selectedProto)
print(tlsHandler.servercerts) # not implemented for tls 1.3
