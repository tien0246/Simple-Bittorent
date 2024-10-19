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
from collections import OrderedDict

session = requests.Session()
peer_port = 50000 + random.randint(0, 5000)
peer_id = hashlib.sha1(str(random.randint(0, sys.maxsize)).encode()).hexdigest()
server_url = ''
username = ''
piece_length = 512 * 1024
torrents_dir = 'torrents'

if not os.path.exists(torrents_dir):
    os.makedirs(torrents_dir)

# Existing functions like create_torrent, upload_torrent, etc.

def calculate_info_hash(info):
    return hashlib.sha1(bencodepy.encode(info)).hexdigest()

# Add this function to parse the .torrent file and extract metadata
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

# Class to manage torrent metadata
class Torrent:
    def __init__(self, torrent_path):
        self.torrent_path = torrent_path
        torrent_data = parse_torrent_file(torrent_path)
        self.info = torrent_data['info']
        self.info_hash = torrent_data['info_hash']
        self.piece_length = torrent_data['piece_length']
        self.pieces = torrent_data['pieces']
        self.num_pieces = torrent_data['num_pieces']
        self.total_length = torrent_data['total_length']
        self.name = torrent_data['name']
        self.pieces_have = [False] * self.num_pieces
        self.piece_hashes = [self.pieces[i*20:(i+1)*20] for i in range(self.num_pieces)]

# Class to manage the overall torrent client state
class TorrentClient:
    def __init__(self, torrent, download_dir='downloads'):
        self.torrent = torrent
        self.peers = []
        self.peer_threads = []
        self.download_dir = download_dir
        self.pieces_have = [False] * self.torrent.num_pieces
        self.pieces_lock = threading.Lock()
        self.peer_id = peer_id.encode('utf-8')[:20]
        self.uploaded = 0
        self.downloaded = 0
        self.left = self.torrent.total_length
        self.block_size = 2 ** 14  # 16KB per request
        if not os.path.exists(self.download_dir):
            os.makedirs(self.download_dir)
        self.file_path = os.path.join(self.download_dir, self.torrent.name)
        self.file = open(self.file_path, 'wb')
        self.file.truncate(self.torrent.total_length)
        self.have_pieces = set()
        self.bitfield = bytearray((self.torrent.num_pieces + 7) // 8)
        self.shutdown_event = threading.Event()
        self.peer_port = peer_port
        self.upload_slots = []
        self.max_upload_slots = 4
        self.piece_manager = PieceManager(self.torrent)

    def start(self):
        # Announce to the tracker
        peers_list = announce(self.torrent.info_hash, 'started', self.peer_port, self.uploaded, self.downloaded, self.left)
        if peers_list:
            print("Received peers from tracker:", peers_list)
            self.peers = peers_list
            # Start a thread to listen for incoming connections
            listener_thread = threading.Thread(target=self.listen_for_peers)
            listener_thread.start()
            # Start connections to peers
            for peer in self.peers:
                peer_thread = threading.Thread(target=self.connect_to_peer, args=(peer,))
                self.peer_threads.append(peer_thread)
                peer_thread.start()
        else:
            print("No peers received from tracker")

    def connect_to_peer(self, peer_info):
        ip = peer_info['ip']
        port = int(peer_info['port'])
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, port))
            peer_connection = PeerConnection(self, sock, peer_info)
            peer_connection.run()
        except Exception as e:
            print(f"Failed to connect to peer {ip}:{port} - {e}")

    def listen_for_peers(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(('', self.peer_port))
        listener.listen(5)
        print(f"Listening for incoming connections on port {self.peer_port}")
        while not self.shutdown_event.is_set():
            try:
                conn, addr = listener.accept()
                print(f"Accepted connection from {addr}")
                peer_info = {'ip': addr[0], 'port': addr[1]}
                peer_thread = threading.Thread(target=self.handle_incoming_peer, args=(conn, peer_info))
                self.peer_threads.append(peer_thread)
                peer_thread.start()
            except Exception as e:
                print(f"Error accepting connections: {e}")
                break
        listener.close()

    def handle_incoming_peer(self, conn, peer_info):
        peer_connection = PeerConnection(self, conn, peer_info, incoming=True)
        peer_connection.run()

# Class to manage individual peer connections
class PeerConnection:
    def __init__(self, client, sock, peer_info, incoming=False):
        self.client = client
        self.sock = sock
        self.peer_info = peer_info
        self.peer_choking = True
        self.peer_interested = False
        self.am_choking = True
        self.am_interested = False
        self.peer_id = None
        self.buffer = b''
        self.incoming = incoming
        self.peer_bitfield = [False] * self.client.torrent.num_pieces
        self.peer_pieces = set()

    def run(self):
        try:
            if not self.incoming:
                self.send_handshake()
            else:
                self.receive_handshake()
            self.communicate()
        except Exception as e:
            print(f"PeerConnection error with {self.peer_info['ip']}:{self.peer_info['port']} - {e}")
        finally:
            self.sock.close()

    def send_handshake(self):
        pstrlen = bytes([19])
        pstr = b'BitTorrent protocol'
        reserved = bytes(8)
        info_hash = bytes.fromhex(self.client.torrent.info_hash)
        peer_id = self.client.peer_id
        handshake = pstrlen + pstr + reserved + info_hash + peer_id
        self.sock.sendall(handshake)
        self.receive_handshake()

    def receive_handshake(self):
        handshake = self.recv_n_bytes(68)
        if len(handshake) < 68:
            raise Exception("Incomplete handshake")
        pstrlen = handshake[0]
        pstr = handshake[1:20]
        if pstr != b'BitTorrent protocol':
            raise Exception("Invalid protocol identifier")
        info_hash = handshake[28:48]
        peer_id = handshake[48:68]
        if info_hash != bytes.fromhex(self.client.torrent.info_hash):
            raise Exception("Info hash does not match")
        self.peer_id = peer_id
        # Send our handshake if we are the server
        if self.incoming:
            self.send_handshake()
        # Send bitfield if we have pieces
        if any(self.client.pieces_have):
            self.send_bitfield()

    def send_bitfield(self):
        bitfield = self.client.bitfield
        msg = self.build_message(5, bitfield)
        self.sock.sendall(msg)

    def build_message(self, msg_id, payload=b''):
        length = len(payload) + 1  # 1 byte for msg_id
        return struct.pack(">I", length) + bytes([msg_id]) + payload

    def recv_n_bytes(self, n):
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                break
            data += chunk
        return data

    def communicate(self):
        while True:
            msg = self.recv_message()
            if msg is None:
                break
            self.handle_message(msg)

    def recv_message(self):
        # Read message length
        length_prefix = self.recv_n_bytes(4)
        if len(length_prefix) < 4:
            return None  # Connection closed
        length = struct.unpack(">I", length_prefix)[0]
        if length == 0:
            return {'id': -1}  # Keep-alive
        msg_id = self.recv_n_bytes(1)
        if len(msg_id) < 1:
            return None
        msg_id = msg_id[0]
        payload_length = length - 1
        payload = self.recv_n_bytes(payload_length)
        if len(payload) < payload_length:
            return None
        return {'id': msg_id, 'payload': payload}

    def handle_message(self, msg):
        msg_id = msg['id']
        payload = msg.get('payload', b'')
        if msg_id == -1:
            # Keep-alive
            pass
        elif msg_id == 0:
            # Choke
            self.peer_choking = True
        elif msg_id == 1:
            # Unchoke
            self.peer_choking = False
            # Now we can send requests
            self.request_piece()
        elif msg_id == 2:
            # Interested
            self.peer_interested = True
            # Decide whether to unchoke
            if self.am_choking:
                self.send_unchoke()
        elif msg_id == 3:
            # Not interested
            self.peer_interested = False
        elif msg_id == 4:
            # Have
            piece_index = struct.unpack(">I", payload)[0]
            self.peer_pieces.add(piece_index)
            self.peer_bitfield[piece_index] = True
            self.update_interest()
        elif msg_id == 5:
            # Bitfield
            self.handle_bitfield(payload)
        elif msg_id == 6:
            # Request
            self.handle_request(payload)
        elif msg_id == 7:
            # Piece
            self.handle_piece(payload)
        elif msg_id == 8:
            # Cancel
            pass  # Not implemented
        elif msg_id == 9:
            # Port
            pass  # Not implemented
        else:
            print(f"Unknown message ID: {msg_id}")

    def handle_bitfield(self, payload):
        for i in range(len(payload)):
            byte = payload[i]
            for j in range(8):
                if i * 8 + j < len(self.peer_bitfield):
                    self.peer_bitfield[i * 8 + j] = (byte >> (7 - j)) & 1
                    if self.peer_bitfield[i * 8 + j]:
                        self.peer_pieces.add(i * 8 + j)
        # Decide whether we are interested
        self.update_interest()

    def update_interest(self):
        interested = False
        for i in range(self.client.torrent.num_pieces):
            if self.peer_bitfield[i] and not self.client.pieces_have[i]:
                interested = True
                break
        if interested and not self.am_interested:
            self.send_interested()
        elif not interested and self.am_interested:
            self.send_not_interested()

    def send_interested(self):
        msg = self.build_message(2)
        self.sock.sendall(msg)
        self.am_interested = True

    def send_not_interested(self):
        msg = self.build_message(3)
        self.sock.sendall(msg)
        self.am_interested = False

    def send_unchoke(self):
        msg = self.build_message(1)
        self.sock.sendall(msg)
        self.am_choking = False

    def request_piece(self):
        # Find next block to request
        piece_index, begin, length = self.client.piece_manager.next_request(self.peer_bitfield)
        if piece_index is None:
            # No blocks to request
            return
        # Build request message
        payload = struct.pack(">III", piece_index, begin, length)
        msg = self.build_message(6, payload)
        self.sock.sendall(msg)

    def handle_piece(self, payload):
        piece_index = struct.unpack(">I", payload[:4])[0]
        begin = struct.unpack(">I", payload[4:8])[0]
        block = payload[8:]
        # Write the block to the file
        with self.client.pieces_lock:
            self.client.file.seek(piece_index * self.client.torrent.piece_length + begin)
            self.client.file.write(block)
            # Update piece manager
            piece_complete = self.client.piece_manager.block_received(piece_index, begin, len(block))
            if piece_complete:
                # Verify piece hash
                self.client.file.flush()
                self.client.file.seek(piece_index * self.client.torrent.piece_length)
                piece_data = self.client.file.read(self.client.torrent.piece_length)
                piece_hash = hashlib.sha1(piece_data).digest()
                expected_hash = self.client.torrent.piece_hashes[piece_index]
                if piece_hash == expected_hash:
                    print(f"Piece {piece_index} verified")
                    self.client.pieces_have[piece_index] = True
                    # Update bitfield
                    self.client.have_pieces.add(piece_index)
                    byte_index = piece_index // 8
                    bit_index = piece_index % 8
                    self.client.bitfield[byte_index] |= (1 << (7 - bit_index))
                    # Notify peers we have this piece
                    self.send_have(piece_index)
                else:
                    print(f"Piece {piece_index} hash mismatch")
                    # Reset blocks_received for this piece
                    self.client.piece_manager.reset_piece(piece_index)
        # Update download progress
        self.client.downloaded += len(block)
        self.client.left -= len(block)
        # Check if we have completed all pieces
        if all(self.client.pieces_have):
            print("Download complete")
            self.client.shutdown_event.set()
            # Send 'completed' event to tracker
            announce(self.client.torrent.info_hash, 'completed', self.client.peer_port, self.client.uploaded, self.client.downloaded, self.client.left)
        else:
            # Request next piece
            self.request_piece()

    def send_have(self, piece_index):
        payload = struct.pack(">I", piece_index)
        msg = self.build_message(4, payload)
        self.sock.sendall(msg)

    def handle_request(self, payload):
        # Parse request
        piece_index = struct.unpack(">I", payload[:4])[0]
        begin = struct.unpack(">I", payload[4:8])[0]
        length = struct.unpack(">I", payload[8:12])[0]
        # Check if we have the piece
        if not self.client.pieces_have[piece_index]:
            return  # Ignore request
        # Read the block from the file
        with self.client.pieces_lock:
            self.client.file.seek(piece_index * self.client.torrent.piece_length + begin)
            block = self.client.file.read(length)
        # Send piece message
        payload = struct.pack(">II", piece_index, begin) + block
        msg = self.build_message(7, payload)
        self.sock.sendall(msg)

# Class to manage piece downloading
class PieceManager:
    def __init__(self, torrent):
        self.torrent = torrent
        self.total_pieces = torrent.num_pieces
        self.piece_length = torrent.piece_length
        self.last_piece_length = torrent.total_length - (self.total_pieces - 1) * self.piece_length
        self.block_size = 2 ** 14  # 16KB per block
        self.total_blocks = 0
        self.blocks_per_piece = []
        self.blocks_received = {}
        for i in range(self.total_pieces):
            if i == self.total_pieces - 1:
                piece_size = self.last_piece_length
            else:
                piece_size = self.piece_length
            num_blocks = (piece_size + self.block_size - 1) // self.block_size
            self.blocks_per_piece.append(num_blocks)
            self.total_blocks += num_blocks
            self.blocks_received[i] = [False] * num_blocks
        self.pieces_lock = threading.Lock()

    def next_request(self, peer_bitfield):
        with self.pieces_lock:
            for piece_index in range(self.total_pieces):
                if not self.is_piece_complete(piece_index) and peer_bitfield[piece_index]:
                    for block_index, received in enumerate(self.blocks_received[piece_index]):
                        if not received:
                            begin = block_index * self.block_size
                            length = min(self.block_size, self.piece_length - begin)
                            return piece_index, begin, length
        return None, None, None

    def block_received(self, piece_index, begin, length):
        with self.pieces_lock:
            block_index = begin // self.block_size
            self.blocks_received[piece_index][block_index] = True
            # Check if piece is complete
            if all(self.blocks_received[piece_index]):
                return True
        return False

    def is_piece_complete(self, piece_index):
        return all(self.blocks_received[piece_index])

    def reset_piece(self, piece_index):
        with self.pieces_lock:
            self.blocks_received[piece_index] = [False] * self.blocks_per_piece[piece_index]

# Modify the announce function to return peers
def announce(info_hash, event, port=None, uploaded=0, downloaded=0, left=0):
    url = f"{server_url}/announce"
    data = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'event': event
    }
    if event == 'started':
        data['port'] = port
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

# Add a function to start the torrent client
def start_torrent(torrent_path):
    torrent = Torrent(torrent_path)
    client = TorrentClient(torrent)
    client.start()

if __name__ == '__main__':
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
            print("8. Start torrent client")
            print("9. Exit")
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
                torrent_path = input("Enter path to torrent file: ")
                start_torrent(torrent_path)
            elif choice == '9':
                break
            else:
                print("Invalid choice")
    except KeyboardInterrupt:
        announce("95acaa0905b98ea184ea9bd2d7c2c916421cbd4c", "stopped", peer_port, 0, 0, 100)
