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

# Global variables
session = requests.Session()
base_url = 'http://localhost:8000'
peer_port = 50000 + random.randint(0, 1000)
peer_id = '-PC0001-' + ''.join(random.choice('0123456789ABCDEF') for _ in range(12))
files_directory = 'files'
torrent_files = {}

# Ensure files directory exists
if not os.path.exists(files_directory):
    os.makedirs(files_directory)

def main():
    load_torrent_files()
    # Start the peer server in a separate thread
    threading.Thread(target=start_peer_server, daemon=True).start()
    while True:
        print("\nSelect an option:")
        print("1. Register")
        print("2. Login")
        print("3. Upload torrent")
        print("4. List torrents")
        print("5. Download torrent")
        print("6. Logout")
        print("7. Exit")
        choice = input("Enter your choice: ")
        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            upload_torrent()
        elif choice == '4':
            list_torrents()
        elif choice == '5':
            download_torrent()
        elif choice == '6':
            logout()
        elif choice == '7':
            exit()
        else:
            print("Invalid choice")

def register():
    username = input("Enter username: ")
    password = input("Enter password: ")
    data = {'username': username, 'password': password}
    url = base_url + '/signup'
    response = session.post(url, json=data)
    if response.status_code == 200:
        print("Registration successful")
    else:
        print("Registration failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")
    data = {'username': username, 'password': password}
    url = base_url + '/login'
    response = session.post(url, json=data)
    if response.status_code == 200:
        print("Login successful")
    else:
        print("Login failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def logout():
    url = base_url + '/logout'
    response = session.post(url)
    if response.status_code == 200:
        print("Logout successful")
    else:
        print("Logout failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def upload_torrent():
    file_name = input("Enter file name to create torrent (must be in 'files' directory): ")
    file_path = os.path.join(files_directory, file_name)
    if not os.path.exists(file_path):
        print("File does not exist")
        return
    file_size = os.path.getsize(file_path)
    piece_length = 512 * 1024  # 512KB
    # Read the file and calculate the pieces
    pieces = []
    with open(file_path, 'rb') as f:
        while True:
            piece = f.read(piece_length)
            if not piece:
                break
            sha1_hash = hashlib.sha1(piece).digest()
            pieces.append(sha1_hash)
    info = {
        'name': file_name,
        'file_size': file_size,
        'piece_length': piece_length,
        'pieces': b''.join(pieces).hex()
    }
    bencoded_info = bencodepy.encode(info)
    info_hash = hashlib.sha1(bencoded_info).hexdigest()
    # Now, send a GET request to /upload_torrent with info_hash, name, file_size
    params = {
        'info_hash': info_hash,
        'name': file_name,
        'file_size': file_size
    }
    url = base_url + '/upload_torrent'
    response = session.get(url, params=params)
    if response.status_code == 200:
        print("Torrent uploaded successfully")
        # Save the torrent info to our local list
        torrent = {
            'info_hash': info_hash,
            'info': info
        }
        torrent_files[info_hash] = torrent
        save_torrent_files()
    else:
        print("Torrent upload failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def list_torrents():
    url = base_url + '/get_torrents'
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

def download_torrent():
    info_hash = input("Enter info_hash of the torrent to download: ")
    torrents = get_torrents()
    if info_hash not in torrents:
        print("Torrent not found")
        return
    torrent_info = torrents[info_hash]
    file_name = torrent_info['name'].decode()
    file_size = int(torrent_info['file_size'])
    piece_length = 512 * 1024  # 512KB
    num_pieces = (file_size + piece_length - 1) // piece_length
    pieces = [None] * num_pieces
    left = file_size
    downloaded = 0
    uploaded = 0
    # Create the torrent info and save it
    info = {
        'name': file_name,
        'file_size': file_size,
        'piece_length': piece_length,
    }
    torrent = {
        'info_hash': info_hash,
        'info': info
    }
    torrent_files[info_hash] = torrent
    save_torrent_files()
    # Announce to the tracker with event='started'
    params = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': peer_port,
        'uploaded': uploaded,
        'downloaded': downloaded,
        'left': left,
        'event': 'started'
    }
    url = base_url + '/announce'
    response = session.get(url, params=params)
    if response.status_code == 200:
        response_dict = bencodepy.decode(response.content)
        peers = response_dict.get(b'peers', {})
        # Now, connect to peers and download pieces
        download_pieces(info_hash, peers, pieces, file_name, file_size, piece_length)
    else:
        print("Announce failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def get_torrents():
    url = base_url + '/get_torrents'
    response = session.get(url)
    torrents = {}
    if response.status_code == 200:
        torrents_data = bencodepy.decode(response.content)
        for info_hash, torrent_info in torrents_data.items():
            info_hash = info_hash.decode()
            torrent_info = {k.decode(): v for k, v in torrent_info.items()}
            torrents[info_hash] = torrent_info
    return torrents

def download_pieces(info_hash, peers, pieces, file_name, file_size, piece_length):
    # Create a set of pieces we need
    needed_pieces = set(range(len(pieces)))
    piece_lock = threading.Lock()
    # Start threads to connect to peers
    threads = []
    for peer_id_key, peer_info in peers.items():
        peer_id_key = peer_id_key.decode()
        peer_info = {k.decode(): v for k, v in peer_info.items()}
        ip = peer_info['ip']
        port = int(peer_info['port'])
        if ip == '127.0.0.1' and port == peer_port:
            continue  # Skip self
        t = threading.Thread(target=download_from_peer, args=(ip, port, info_hash, needed_pieces, pieces, piece_lock, piece_length))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    # After downloading all pieces, write the file
    with open(os.path.join(files_directory, file_name), 'wb') as f:
        for piece in pieces:
            f.write(piece)
    print("Download completed")
    # Announce to tracker with event='completed'
    params = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': peer_port,
        'uploaded': 0,
        'downloaded': file_size,
        'left': 0,
        'event': 'completed'
    }
    url = base_url + '/announce'
    response = session.get(url, params=params)
    if response.status_code == 200:
        print("Announce completed")
    else:
        print("Announce failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def download_from_peer(ip, port, info_hash, needed_pieces, pieces, piece_lock, piece_length):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        # Send handshake
        handshake = {
            'type': 'handshake',
            'info_hash': info_hash,
            'peer_id': peer_id
        }
        send_message(sock, handshake)
        # Receive handshake
        message = recv_message(sock)
        if not message or message.get('type') != 'handshake':
            print("Invalid handshake from peer", ip, port)
            sock.close()
            return
        # Now, request pieces
        while True:
            with piece_lock:
                if not needed_pieces:
                    break
                index = needed_pieces.pop()
            request = {
                'type': 'request',
                'index': index
            }
            send_message(sock, request)
            # Receive piece
            message = recv_message(sock)
            if message and message.get('type') == 'piece' and message.get('index') == index:
                data_length = message.get('data_length')
                piece_data = recv_all(sock, data_length)
                if not piece_data:
                    print("Failed to receive piece data from", ip, port)
                    with piece_lock:
                        needed_pieces.add(index)
                    continue
                pieces[index] = piece_data
                print("Downloaded piece", index, "from", ip, port)
            else:
                print("Invalid piece message from", ip, port)
                with piece_lock:
                    needed_pieces.add(index)
    except Exception as e:
        print("Error downloading from peer", ip, port, e)
        with piece_lock:
            needed_pieces.update(needed_pieces)
    finally:
        sock.close()

def start_peer_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('', peer_port))
    server_socket.listen(5)
    print("Peer server started on port", peer_port)
    while True:
        client_socket, addr = server_socket.accept()
        threading.Thread(target=handle_peer_connection, args=(client_socket, addr), daemon=True).start()

def handle_peer_connection(client_socket, addr):
    try:
        # Receive handshake
        message = recv_message(client_socket)
        if not message or message.get('type') != 'handshake':
            print("Invalid handshake from", addr)
            client_socket.close()
            return
        peer_info_hash = message.get('info_hash')
        peer_peer_id = message.get('peer_id')
        # Send handshake
        handshake = {
            'type': 'handshake',
            'info_hash': peer_info_hash,
            'peer_id': peer_id
        }
        send_message(client_socket, handshake)
        # Now, handle requests
        while True:
            message = recv_message(client_socket)
            if not message:
                break
            if message.get('type') == 'request':
                index = message.get('index')
                # Read the piece data
                piece_data = get_piece_data(peer_info_hash, index)
                if piece_data is None:
                    print("Do not have piece", index)
                    continue
                piece_message = {
                    'type': 'piece',
                    'index': index,
                    'data_length': len(piece_data)
                }
                send_message(client_socket, piece_message)
                client_socket.sendall(piece_data)
    except Exception as e:
        print("Error handling peer connection:", e)
    finally:
        client_socket.close()

def get_piece_data(info_hash, index):
    # Get the file name from 'torrent_files' or 'files_directory'
    torrent = torrent_files.get(info_hash)
    if not torrent:
        print("Torrent not found for info_hash", info_hash)
        return None
    file_name = torrent['info']['name']
    piece_length = torrent['info']['piece_length']
    file_path = os.path.join(files_directory, file_name)
    if not os.path.exists(file_path):
        print("File not found:", file_path)
        return None
    with open(file_path, 'rb') as f:
        f.seek(index * piece_length)
        piece_data = f.read(piece_length)
        return piece_data

def send_message(sock, message):
    data = json.dumps(message).encode()
    length = struct.pack('>I', len(data))
    sock.sendall(length + data)

def recv_message(sock):
    length_data = recv_all(sock, 4)
    if not length_data:
        return None
    length = struct.unpack('>I', length_data)[0]
    data = recv_all(sock, length)
    if not data:
        return None
    message = json.loads(data.decode())
    return message

def recv_all(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def load_torrent_files():
    global torrent_files
    if os.path.exists('torrent_files.json'):
        with open('torrent_files.json', 'r') as f:
            torrent_files = json.load(f)
    else:
        torrent_files = {}

def save_torrent_files():
    with open('torrent_files.json', 'w') as f:
        json.dump(torrent_files, f)

if __name__ == '__main__':
    main()
