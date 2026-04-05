import socket
from cryptography.hazmat.primitives import serialization
from dotenv import load_dotenv
import os

load_dotenv()
HOST = os.getenv('HOST')
PORT = int(os.getenv('PORT'))


def connect(mode: str) -> socket.socket:
    if mode == 'server':
        s = socket.socket()
        s.bind((HOST, PORT))
        s.listen(1)
        print('Waiting for connection...')
        conn, _ = s.accept()
    else:
        conn = socket.socket()
        conn.connect((HOST, PORT))
    print('Connected!')
    return conn

def exchange_pubkey(conn: socket.socket, my_pub):
    '''Send my public key and receive the other party's.'''
    conn.send(my_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    return serialization.load_pem_public_key(conn.recv(2048))

def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError('Connection closed unexpectedly')
        data += chunk
    return data