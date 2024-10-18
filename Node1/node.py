import threading
import socket
import requests
import hashlib
import bencodepy  # type: ignore
import json
import time
import os
import sys
import random
from collections import OrderedDict

session = requests.Session()
# lock = threading.Lock()
peer_port = 50000 + random.randint(0, 5000)
peer_id = hashlib.sha1(str(random.getrandbits(160)).encode()).digest()
server_url = ''
username = ''
piece_length = 512 * 1024

def create_torrent(path, tracker_url):
    if not os.path.exists(path):
        print("File or directory does not exist")
        return

    pieces = []
    name = os.path.basename(path).encode('utf-8')

    if os.path.isfile(path):
        # Single file
        file_size = os.path.getsize(path)

        with open(path, 'rb') as f:
            while True:
                piece = f.read(piece_length)
                if not piece:
                    break
                pieces.append(hashlib.sha1(piece).digest())

        pieces_concatenated = b''.join(pieces)

        info = OrderedDict()
        info[b'length'] = file_size
        info[b'name'] = name
        info[b'piece length'] = piece_length
        info[b'pieces'] = pieces_concatenated

    else:
        # Multiple files
        files = []
        total_size = 0

        for root, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                file_size = os.path.getsize(file_path)
                total_size += file_size
                relative_path = os.path.relpath(file_path, path)
                path_components = [component.encode('utf-8') for component in relative_path.split(os.sep)]
                files.append(OrderedDict([(b'length', file_size), (b'path', path_components)]))

                with open(file_path, 'rb') as f:
                    while True:
                        piece = f.read(piece_length)
                        if not piece:
                            break
                        if len(piece) < piece_length and f != filenames[-1]:
                            piece += f.read(piece_length - len(piece))
                        pieces.append(hashlib.sha1(piece).digest())

        pieces_concatenated = b''.join(pieces)

        info = OrderedDict()
        info[b'files'] = files
        info[b'name'] = name
        info[b'piece length'] = piece_length
        info[b'pieces'] = pieces_concatenated

    info = OrderedDict(sorted(info.items()))

    bencoded_info = bencodepy.encode(info)
    info_hash = hashlib.sha1(bencoded_info).hexdigest()
    print(f'Info hash: {info_hash}')

    torrent = OrderedDict()
    torrent[b'announce'] = tracker_url.encode('utf-8')
    torrent[b'creation date'] = int(time.time())
    torrent[b'created by'] = username.encode('utf-8')
    torrent[b'info'] = info

    torrent = OrderedDict(sorted(torrent.items()))
    torrent_file = bencodepy.encode(torrent)
    torrent_filename = name.decode('utf-8') + '.torrent'
    with open(torrent_filename, 'wb') as f:
        f.write(torrent_file)











def register(username, password):
    data = {'username': username, 'password': password}
    url = server_url + '/signup'
    response = session.post(url, json=data)
    if response.status_code == 200:
        print("Registration successful")
    else:
        print("Registration failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def login(username, password):
    data = {'username': username, 'password': password}
    url = server_url + '/login'
    response = session.post(url, json=data)
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def logout():
    url = server_url + '/logout'
    response = session.post(url)
    if response.status_code == 200:
        print("Logout successful")
    else:
        print("Logout failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def list_torrents():
    url = server_url + '/list_torrents'
    response = session.get(url)
    if response.status_code == 200:
        torrents = bencodepy.decode(response.content)
        for info_hash, torrent_info in torrents.items():
            info_hash = info_hash.decode()
            torrent_info = {k.decode(): v for k, v in torrent_info.items()}
            print("Info Hash:", info_hash)
            print("Name:", torrent_info['name'].decode())
            print("File Size:", torrent_info['file_size'])
            print("Uploaded by:", torrent_info['created_by'].decode())
            print("Date Uploaded:", time.ctime(torrent_info['date_uploaded']))
            print("Seeders:", torrent_info['seeder'])
            print("Leechers:", torrent_info['leecher'])
            print("Completed:", torrent_info['completed'])
            print("-" * 20)
    else:
        print("Failed to get torrents:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

if __name__ == '__main__':
    server_url = 'http://localhost:8000'
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Logout")
        print("4. List torrents")
        print("5. Create torrent")
        print("6. Exit")
        choice = input("Enter choice: ")
        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            register(username, password)
        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            login(username, password)
        elif choice == '3':
            logout()
        elif choice == '4':
            list_torrents()
        elif choice == '5':
            path = input("Enter path to file or directory: ")
            create_torrent(path, server_url)
        elif choice == '6':
            break
        else:
            print("Invalid choice")
    