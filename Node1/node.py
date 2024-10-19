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
import struct

session = requests.Session()
# lock = threading.Lock()
peer_port = 50000 + random.randint(0, 5000)
peer_id = hashlib.sha1(str(random.randint(0, sys.maxsize)).encode()).hexdigest()
server_url = ''
username = ''
piece_length = 512 * 1024
torrents_dir = 'torrents'

if not os.path.exists(torrents_dir):
    os.makedirs(torrents_dir)

class Connection:
    def __init__(self, info_hash, client_peer_id):
        self.info_hash = info_hash
        self.client_peer_id = client_peer_id

    def create_handshake_message(self):
        pstr = b"BitTorrent protocol"
        pstrlen = len(pstr)
        reserved = b'\x00' * 8
        handshake = struct.pack("!B", pstrlen) + pstr + reserved + self.info_hash + self.client_peer_id
        return handshake

    def connect_to_peer(self, peer_ip, peer_port, peer_id):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer_ip, peer_port))

            handshake_message = self.create_handshake_message()
            sock.sendall(handshake_message)

            response = sock.recv(68)

            if len(response) != 68:
                print("Failed to receive a proper handshake response.")
                sock.close()
                return None
            
            if response[:20] != handshake_message[:20]:
                print("Invalid handshake received. Closing connection.")
                sock.close()
                return None

            received_info_hash = response[28:48]
            received_peer_id = response[48:68]
            
            if received_info_hash != self.info_hash:
                print("Info hash mismatch. Closing connection.")
                sock.close()
                return None

            if received_peer_id != peer_id:
                print("Connected wrong peer. Closing connection.")
                sock.close()
                return None
            
            print(f"Connected to peer {peer_ip}:{peer_port}")

            return sock
        except Exception as e:
            print(f"Failed to connect to peer {peer_ip}:{peer_port}: {e}")
            return None
        
    def handle_client(self, client_sock, client_addr, info_hash, create_handshake_message):
        try:
            print(f"Received connection from {client_addr}")

            handshake = client_sock.recv(68)
            if len(handshake) != 68:
                print("Invalid handshake received. Closing connection.")
                client_sock.close()
                return

            received_info_hash = handshake[28:48]
            if received_info_hash != info_hash:
                print("Info hash mismatch. Disconnecting.")
                client_sock.close()
                return

            response_handshake = create_handshake_message()
            client_sock.send(response_handshake)

            print(f"Handshake successful with peer {client_addr}")

            while True:
                data = client_sock.recv(1024)
                if not data:
                    break
                print(f"Received data from {client_addr}: {data.decode()}")

        except Exception as e:
            print(f"Error occurred while handling client {client_addr}: {e}")
        finally:
            client_sock.close()

    def listen_for_handshake(self, port):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(('', port))
            server_sock.listen(5)
            print(f"Listening for incoming connections on port {port}...")

            while True:
                client_sock, client_addr = server_sock.accept()

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_addr, self.info_hash, self.create_handshake_message)
                )
                client_thread.start()

        except Exception as e:
            print(f"Error occurred while listening for handshakes: {e}")
        finally:
            server_sock.close()

    def start_server_in_thread(self, port):
        server_thread = threading.Thread(target=self.listen_for_handshake, args=(port,))
        server_thread.daemon = True
        server_thread.start()
        print(f"Server started on port {port} in a separate thread.")

    def run(self):
        peer_ip = '0.0.0.0'
        peer_port = 9001
        peer_id = bytes.fromhex(input("Enter peer ID: "))
        s = self.connect_to_peer(peer_ip, peer_port, peer_id)
        if s:
            s.send(b'Hello, world!')
            s.close()
        else:
            print("Failed to connect to peer")

def create_torrent(path, tracker_url, output_file=None):
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

        info = {
            'length': file_size,
            'name': name,
            'piece length': piece_length,
            'pieces': pieces_concatenated
        }

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
                files.append({'length': file_size, 'path': path_components})

                with open(file_path, 'rb') as f:
                    while True:
                        piece = f.read(piece_length)
                        if not piece:
                            break
                        if len(piece) < piece_length and f != filenames[-1]:
                            piece += f.read(piece_length - len(piece))
                        pieces.append(hashlib.sha1(piece).digest())

        pieces_concatenated = b''.join(pieces)

        info = {
            'files': files,
            'name': name,
            'piece length': piece_length,
            'pieces': pieces_concatenated
        }

    torrent = {
        'announce': tracker_url,
        'creation date': int(time.time()),
        'created by': username,
        'info': info
    }

    print(calculate_info_hash(info))

    torrent_file = bencodepy.encode(torrent)
    torrent_filename = (output_file or calculate_info_hash(info)) + '.torrent'

    torrent_path = os.path.join(torrents_dir, torrent_filename)
    with open(torrent_path, 'wb') as f:
        f.write(torrent_file)

def parse_torrent_file(torrent_path):
    with open(torrent_path, 'rb') as f:
        torrent_data = f.read()
    meta = bencodepy.decode(torrent_data)
    info = meta[b'info']
    info_hash = calculate_info_hash(info)
    piece_length = info[b'piece length']
    pieces = info[b'pieces']
    num_pieces = len(pieces) // 20
    total_length = 0
    if b'length' in info:
        total_length = info[b'length']
    elif b'files' in info:
        for file_info in info[b'files']:
            total_length += file_info[b'length']
    else:
        raise ValueError("Invalid torrent file: no length or files")
    name = info[b'name'].decode('utf-8')
    return {
        'info': info,
        'info_hash': info_hash,
        'piece_length': piece_length,
        'pieces': pieces,
        'num_pieces': num_pieces,
        'total_length': total_length,
        'name': name
    }

def calculate_info_hash(info):
    return hashlib.sha1(bencodepy.encode(info)).hexdigest()

def upload_torrent(torrent_path):
    url = f"{server_url}/upload_torrent"
    file = {'torrent': open(torrent_path, 'rb')}
    torrent = bencodepy.decode(open(torrent_path, 'rb').read())
    data = {
        'info_hash': calculate_info_hash(torrent[b'info']),
        'name': torrent[b'info'][b'name'].decode(),
    }
    if b'length' in torrent[b'info']:
        data['file_size'] = torrent[b'info'][b'length']
    else:
        files_info = [
            {'length': file[b'length'], 'path': [p.decode('utf-8') for p in file[b'path']]}
            for file in torrent[b'info'][b'files']
        ]
        data['path'] = json.dumps(files_info) 
        print(data['path'])

    try:
        response = session.post(url, files=file, data=data)
        if response.status_code == 200:
            print("Torrent uploaded successfully")
        else:
            print("Failed to upload torrent:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())
    except requests.exceptions.ConnectionError:
        print("Failed to connect to server")
    except Exception as e:
        print("An error occurred:", e)

def download_torrent(info_hash):
    url = f"{server_url}/download_torrent/{info_hash}"
    try:
        response = session.get(url)
        if response.status_code == 200:
            torrent_filename = info_hash + '.torrent'
            torrent_path = os.path.join(torrents_dir, torrent_filename)
            with open(torrent_path, 'wb') as f:
                f.write(response.content)
            print("Torrent downloaded successfully")
        else:
            print("Failed to download torrent:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())
    except requests.exceptions.ConnectionError:
        print("Failed to connect to server")
    except Exception as e:
        print("An error occurred:", e)

def scrape(info_hash):
    url = f"{server_url}/scrape"
    data = {'info_hash': info_hash}
    response = session.get(url, params=data)
    if response.status_code == 200:
        response_dict = bencodepy.decode(response.content)
        print("Seeder:", response_dict['seeder'])
        print("Leecher:", response_dict['leecher'])
        print("Completed:", response_dict['completed'])
    else:
        print("Failed to scrape:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def announce(info_hash, event, port=None, uploaded=0, downloaded=0, left=0):
    url = f"{server_url}/announce"
    data = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'event': event
    }
    if event == 'started':
        data['port'] = peer_port
        data['uploaded'] = uploaded
        data['downloaded'] = downloaded
        data['left'] = left
    try:
        response = session.get(url, params=data)
        if response.status_code == 200:
            response_dict = bencodepy.decode(response.content)
            peers = response_dict.get(b'peers', {})
            peers_list = []
            for peerid, peer_info in peers.items():
                peerid = peerid.decode()
                peer_info = {k.decode(): (v.decode() if isinstance(v, bytes) else v) for k, v in peer_info.items()}
                peer_info['peerid'] = peerid
                peers_list.append(peer_info)
            return peers_list
        else:
            print("Failed to announce:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())
    except Exception as e:
        print("An error occurred:", e)

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
            if 'path' in torrent_info:
                print("Files:")
                file_size = 0
                for file in torrent_info['path']:
                    path = file[b'path'] if b'path' in file else file['path']
                    length = file[b'length'] if b'length' in file else file['length']
                    file_size += length
                    print("  -", os.path.join(*[p.decode('utf-8') for p in path]), f"({length} bytes)")
                print("File Size:", file_size, "bytes")
            else:
                print("File Size:", torrent_info['file_size'], "bytes")
            print("Uploaded by:", torrent_info['created_by'].decode())
            print("Date Uploaded:", time.ctime(torrent_info['date_uploaded']))
            print("Seeders:", torrent_info['seeder'])
            print("Leechers:", torrent_info['leecher'])
            print("Completed:", torrent_info['completed'])
            print("-" * 20)
    else:
        print("Failed to get torrents:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())




if __name__ == '__main__':
    # server_url = 'http://10.0.221.122:8000'
    server_url = 'http://0.0.0.0:8000'
    try:
        while True:
            print("1. Register")
            print("2. Login")
            print("3. Logout")
            print("4. List torrents")
            print("5. Create torrent")
            print("6. Upload torrent")
            print("7. Download torrent")
            print("9. Send Handshake")
            print("10. Listen for Handshake")
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
                tracker_url = input("Enter tracker URL: ")
                create_torrent(path, tracker_url)
            elif choice == '6':
                torrent_path = input("Enter path to torrent file: ")
                upload_torrent(torrent_path)
            elif choice == '7':
                info_hash = input("Enter info hash: ")
                download_torrent(info_hash)
            elif choice == '8':
                print(announce("95acaa0905b98ea184ea9bd2d7c2c916421cbd4c", "started", 9001, 0, 0, 0))
            elif choice == '9':
                # peer_ip = input("Enter peer IP: ")
                # peer_port = int(input("Enter peer port: "))
                info_hash = bytes.fromhex('95acaa0905b98ea184ea9bd2d7c2c916421cbd4c')
                connect = Connection(info_hash, bytes.fromhex(peer_id))
                connect.run()
            elif choice == '10':
                # port = int(input("Enter peer port: "))
                port = 9001
                print("Listening on port", port)
                print("Peer ID:", peer_id)
                # info_hash = bytes.fromhex(input("Enter info hash (hex): "))
                info_hash = bytes.fromhex('95acaa0905b98ea184ea9bd2d7c2c916421cbd4c')
                peerid = bytes.fromhex(peer_id)
                connect = Connection(info_hash, peerid)
                # connect.listen_for_handshake(port)
                connect.start_server_in_thread(port)
            else:
                print("Invalid choice")
    except KeyboardInterrupt:
        announce("95acaa0905b98ea184ea9bd2d7c2c916421cbd4c", "stopped", 9001, 0, 0, 100)