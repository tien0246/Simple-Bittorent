from concurrent.futures import ThreadPoolExecutor
import threading
from threading import Thread
from queue import Queue
import socket
import requests
import hashlib
import bencodepy
import json
import time
import os
import sys
import random
import struct
import atexit
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import questionary
from alive_progress import alive_bar
from tabulate import tabulate

DEBUG = False

current_dir = os.path.dirname(os.path.abspath(__file__))

session = requests.Session()
peer_port = 50000 + random.randint(0, 5000)
peer_id = hashlib.sha1(str(random.randint(0, sys.maxsize)).encode()).hexdigest()
server_url = 'http://103.116.52.225:8000'
# public_ip = requests.get('https://ipinfo.io/ip').text.strip()
username = ''
piece_length = 512 * 1024
block_size = 16 * 1024
torrents_dir = os.path.join(current_dir, 'torrents')
downloads_dir = os.path.join(current_dir, 'downloads')
piece_history = {}

if not os.path.exists(torrents_dir):
    os.makedirs(torrents_dir)
if not os.path.exists(downloads_dir):
    os.makedirs(downloads_dir)
class Torrent:
    def __init__(self, torrent_path, pieces = None):
        self.torrent_path = torrent_path
        torrent_data = parse_torrent_file(torrent_path)
        self.info = torrent_data['info']
        self.info_hash = torrent_data['info_hash']
        self.piece_length = torrent_data['piece_length']
        self.pieces = torrent_data['pieces']
        self.num_pieces = torrent_data['num_pieces']
        self.total_length = torrent_data['total_length']
        self.name = torrent_data['name']
        self.paths = torrent_data['paths']
        self.pieces_have = [False] * self.num_pieces if pieces is None else pieces
        self.piece_hashes = [self.pieces[i*20:(i+1)*20] for i in range(self.num_pieces)]
        self.download_bar = None
   

def create_info(path):
    if not os.path.exists(path):
        raise FileNotFoundError("File or directory does not exist")
    pieces = []
    name = os.path.basename(path).encode('utf-8')
    total_size = 0

    if os.path.isfile(path):
        file_size = os.path.getsize(path)
        total_size = file_size
        num_pieces = (file_size + piece_length - 1) // piece_length
        with open(path, 'rb') as f, alive_bar(num_pieces, title='Creating torrent for single file') as bar:
            while True:
                piece = f.read(piece_length)
                if not piece:
                    break
                pieces.append(hashlib.sha1(piece).digest())
                bar()
        pieces_concatenated = b''.join(pieces)
        info = {
            'length': file_size,
            'name': name,
            'piece length': piece_length,
            'pieces': pieces_concatenated
        }
    else:
        files = []
        buffer = b''
        for root, _, filenames in os.walk(path):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                file_size = os.path.getsize(file_path)
                num_pieces = (file_size + piece_length - 1) // piece_length
                total_size += file_size
                relative_path = os.path.relpath(file_path, path)
                path_components = [component.encode('utf-8') for component in relative_path.split(os.sep)]
                files.append({'length': file_size, 'path': path_components})
                with open(file_path, 'rb') as f, alive_bar(num_pieces, title='Creating torrent for file: ' + filename) as bar:
                    while True:
                        chunk = f.read(piece_length - len(buffer))
                        if not chunk:
                            break
                        buffer += chunk
                        if len(buffer) >= piece_length:
                            piece_data = buffer[:piece_length]
                            pieces.append(hashlib.sha1(piece_data).digest())
                            buffer = buffer[piece_length:]
                        bar()
        if buffer:
            pieces.append(hashlib.sha1(buffer).digest())
        pieces_concatenated = b''.join(pieces)
        info = {
            'files': files,
            'name': name,
            'piece length': piece_length,
            'pieces': pieces_concatenated
        }
    return info
    
def create_torrent(path, tracker_url, output_file=None):
    try:
        info = create_info(path)
    except FileNotFoundError as e:
        print(e)
        return
    torrent = {
        'announce': tracker_url,
        'creation date': int(time.time()),
        'created by': username.encode('utf-8'),
        'info': info
    }
    info_hash = calculate_info_hash(info)
    torrent_file = bencodepy.encode(torrent)
    torrent_filename = (output_file or info_hash) + '.torrent'
    torrent_path = os.path.join(torrents_dir, torrent_filename)
    with open(torrent_path, 'wb') as f:
        f.write(torrent_file)
    print(f"Torrent file created at: {torrent_path}")

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
    paths = []
    if b'length' in info:
        total_length = info[b'length']
    elif b'files' in info:
        paths = []
        for file_info in info[b'files']:
            total_length += file_info[b'length']
            file_path = [p.decode() for p in file_info[b'path']]
            paths.append({'length': file_info[b'length'], 'path': file_path})
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
        'name': name,
        'paths': paths
    }

def calculate_info_hash(info):
    return hashlib.sha1(bencodepy.encode(info)).hexdigest()
class BiMap:
    def __init__(self):
        self.forward = {}
        self.backward = {}
    def add(self, key, value):
        if key not in self.forward:
            self.forward[key] = set()
        if value not in self.backward:
            self.backward[value] = set()
        self.forward[key].add(value)
        self.backward[value].add(key)
    def remove(self, key, value):
        if key in self.forward:
            self.forward[key].discard(value)
            if not self.forward[key]:
                del self.forward[key]
        if value in self.backward:
            self.backward[value].discard(key)
            if not self.backward[value]:
                del self.backward[value]
    def get_by_key(self, key):
        return self.forward.get(key, set())
    def get_by_value(self, value):
        return self.backward.get(value, set())
    def __repr__(self):
        return f"BiMap(forward={self.forward}, backward={self.backward})"

class Connection:
    def __init__(self, torrent, client_peer_id):
        self.torrent = torrent
        self.client_peer_id = client_peer_id
        self.lock = threading.Lock()
        self.request_pieces = Queue()
        self.downloaded_block = [{} for _ in range(torrent.num_pieces)]
        self.retry_counts = {}
        self.max_retries = 3
        self.peers = []
        self.piece_peer_map = BiMap()
        self.downloading_thread = 0
        self.aes_key = {}
        self.stop = False

    def send_message(self, sock, msg_id, payload=b''):
        length = 1 + len(payload)
        message = struct.pack("!I", length) + struct.pack("!B", msg_id) + payload
        sock.sendall(message)

    def _recv_all(self, sock, n):
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def receive_message(self, sock):
        try:
            length_bytes = self._recv_all(sock, 4)
            if not length_bytes:
                return None, None
            length = struct.unpack("!I", length_bytes)[0]
            if length == 0:
                return None, None
            msg_id_bytes = self._recv_all(sock, 1)
            if not msg_id_bytes:
                return None, None
            msg_id = struct.unpack("!B", msg_id_bytes)[0]
            payload = b''
            if length > 1:
                payload = self._recv_all(sock, length - 1)
            return msg_id, payload
        except Exception as e:
            if DEBUG:
                print("Failed to receive message:", e)
            return None, None

    def create_handshake_message(self):
        pstr = b"BitTorrent protocol"
        pstrlen = len(pstr)
        reserved = b'\x00' * 8
        handshake = struct.pack("!B", pstrlen) + pstr + reserved + bytes.fromhex(self.torrent.info_hash) + self.client_peer_id
        return handshake
    
    def create_bitfield(self, pieces):
        bitfield = bytearray()
        byte = 0
        for i, piece in enumerate(pieces):
            if piece:
                byte |= (1 << (7 - (i % 8)))
            if (i % 8) == 7:
                bitfield.append(byte)
                byte = 0
        if len(pieces) % 8 != 0:
            bitfield.append(byte)
        return bytes(bitfield)
    
    def parse_bitfield(self, bitfield, num_pieces):
        peer_pieces = [False] * num_pieces
        for i in range(num_pieces):
            byte_index = i // 8
            bit_index = 7 - (i % 8)
            if byte_index < len(bitfield):
                if bitfield[byte_index] & (1 << bit_index):
                    peer_pieces[i] = True
        return peer_pieces
    
    def send_interested(self, sock, is_interested):
        if is_interested:
            self.send_message(sock, 2, self.aes_key[0])
            if DEBUG:
                print("Sent Interested")
        else:
            self.send_message(sock, 3)
            if DEBUG:
                print("Sent Not Interested")
    
    def process_message(self, sock, msg_id, payload):
        if msg_id == 0:
            pass
        elif msg_id == 1:
            if DEBUG:
                print("Unchoke")
        elif msg_id == 2:
            if DEBUG:
                print("Interested")
            self.send_message(sock, 1)
        elif msg_id == 3:
            if DEBUG:
                print("Not interested")
            sock.close()
        elif msg_id == 4:
            if DEBUG:
                print("Have")
            self.update_bitfield(sock, int.from_bytes(payload, byteorder='big'))
        elif msg_id == 5:
            if DEBUG:
                print("Bitfield")
            have_pieces = self.parse_bitfield(payload, self.torrent.num_pieces)
            self.send_interested(sock, have_pieces)
        elif msg_id == 6:
            if DEBUG:
                print("Request")
            self.handle_request(sock, payload)
        elif msg_id == 7:
            if DEBUG:
                print("Piece")
            self.handle_piece(sock, payload)
        elif msg_id == 8:
            if DEBUG:
                print("Cancel")
        elif msg_id == 9:
            if DEBUG:
                print("Port")
        else:
            if DEBUG:
                print("Unknown message ID")

    def update_request_pieces(self, peer_id, peer_bitfield, random_first_piece = False):
        pieces_have = {i for i, has_piece in enumerate(peer_bitfield) if has_piece}
        for piece_index in pieces_have:
            self.piece_peer_map.add(piece_index, peer_id)
        piece_count = {}
        if self.request_pieces.empty():
            piece_count = {i: 0 for i, piece_have in enumerate(self.torrent.pieces_have) if not piece_have}
        else:
            while not self.request_pieces.empty():
                piece_count[self.request_pieces.get()] = 0
        for peer in self.peers:
            if 'bitfield' not in peer:
                continue
            for index, has_piece in enumerate(peer['bitfield']):
                if has_piece and index in piece_count:
                    piece_count[index] += 1
        if random_first_piece:
            first_piece = random.choice(list(piece_count.keys()))
            piece_count[first_piece] -= 1
        with self.lock:
            while not self.request_pieces.empty():
                self.request_pieces.get()
        for piece_index in sorted(piece_count, key=lambda x: piece_count[x]):
            with self.lock:
                self.request_pieces.put(piece_index)

        if DEBUG:
            print(f"Request pieces sorted by rarity: {list(self.request_pieces.queue)}")

    def download_progress(self):
        with alive_bar(self.torrent.num_pieces, title='Downloading', manual=True, bar='blocks') as bar:
            while not all(self.torrent.pieces_have):
                bar(sum(self.torrent.pieces_have) / self.torrent.num_pieces)
                time.sleep(1)

    def run(self, peers):
            if not peers:
                print('No peer found.')
                return
            peers = [peer for peer in peers if peer['peerid'] != self.client_peer_id and peer['port'] != peer_port]
            self.peers = peers
            if not peers:
                print("No peers to connect....")
                time.sleep(5)
                return

            max_workers = 5
            with alive_bar(self.torrent.num_pieces, title='Downloading', bar='smooth', theme='smooth') as self.download_bar:
                for have in self.torrent.pieces_have:
                    if have:
                        self.download_bar()
                while not all(self.torrent.pieces_have) and not self.stop:
                    try:
                        if self.downloading_thread >= max_workers:
                                time.sleep(5)
                                continue
                        if not peers:
                            print("No peers to connect...")
                            break
                        for peer in self.peers:
                            if self.downloading_thread >= max_workers:
                                break
                            if DEBUG:
                                print(f"Connecting to peer {peer['ip']}:{peer['port']}...")
                            download_thread = Thread(target=self.handle_peer_connection, args=(peer,))
                            download_thread.start()
                    except KeyboardInterrupt:
                        self.stop = True
                        print("Download interrupted. Stopping leecher...")
                        break 
            while self.downloading_thread > 0:
                pass
            if not self.stop and all(self.torrent.pieces_have):
                if self.verify_file_hash():
                    choice = questionary.select("Download completed. Do you wanna keep being a seeder?", choices=['Yes', 'No']).ask()
                    if choice == 'No':
                        self.stop = True
                        announce(self.torrent.info_hash, 'stopped', port=peer_port)
                        return

    def handle_peer_connection(self, peer):
        self.downloading_thread += 1
        try:
            sock = None
            if all(self.torrent.pieces_have):
                return True
            sock = self.connect_to_peer(peer)
            if not sock:
                self.peers.remove(peer)
                return False
            self.peers.remove(peer)
            peer['sock'] = sock
            self.peers.append(peer)
            self.retry_counts[peer['peerid']] = [0] * self.torrent.num_pieces
            self.download_peer(peer)
            return True       
        except Exception as e:
            if DEBUG:
                print(f"Error handling peer connection: {e}")
            return
        finally:
            self.downloading_thread -= 1
    
    def download_peer(self, peer):
        try:
            if 'sock' not in peer or peer['sock'].fileno() == -1:
                self.peers.remove(peer)
                return
            sock = peer['sock']
            current_piece_index = None
            progress = 0
            done = False
            while not all(self.torrent.pieces_have) and not self.stop:
                if done == True:
                    if not self.request_pieces.empty():
                        current_piece_index = self.request_pieces.get()
                        self.start_request(sock, current_piece_index)
                        done = False
                    else:
                        continue
                try:
                    msg_id, payload = self.receive_message(sock)
                    if msg_id is None:
                        if not all(self.torrent.pieces_have) and current_piece_index is not None:
                            if DEBUG:
                                print('Cannot receive message')
                            if (self.retry_pieces(current_piece_index, peer['peerid'])):
                                continue
                            else: 
                                break
                except:
                    if not all(self.torrent.pieces_have) and current_piece_index is not None:
                        if (self.retry_pieces(current_piece_index, peer['peerid'])):
                            time.sleep(2)
                            continue
                        else: 
                            break
                if DEBUG:
                    print(f"Received message ID {msg_id}")
                if msg_id == 7:
                    finished, verified = self.handle_piece(payload)
                    if finished == False:
                        progress += block_size
                        self.start_request(sock, current_piece_index, progress)
                        continue
                    if finished and verified:
                        self.torrent.pieces_have[current_piece_index] = True
                        with self.lock:
                            for peer in reversed(self.peers):
                                if 'sock' not in peer or peer['sock'].fileno() == -1:
                                    continue
                                try:
                                    self.send_message(peer['sock'], 4, struct.pack("!I", current_piece_index))
                                except:
                                    if DEBUG:
                                        print(f"Cannot send have message to {peer['ip']}:{peer['port']}")
                                    continue
                        if not self.request_pieces.empty():
                            current_piece_index = self.request_pieces.get()
                            self.start_request(sock, current_piece_index)
                        else:
                            done = True
                        progress = 0
                        self.download_bar()
                        continue
                    if finished is None or (finished and not verified):
                        progress = 0
                        if self.retry_pieces(current_piece_index, peer['peerid']):
                            self.start_request(sock, current_piece_index)
                        else:
                            if not self.request_pieces.empty():
                                self.request_pieces.get()
                                self.start_request(sock, current_piece_index)
                            else:
                                done = True
                        continue
                if msg_id == 5:
                    have_pieces = self.parse_bitfield(payload, self.torrent.num_pieces)
                    peer['bitfield'] = have_pieces
                    is_interested = any(have_pieces[i] and not self.torrent.pieces_have[i] for i in range(len(have_pieces)))
                    if is_interested:
                        self.update_request_pieces(peer['peerid'], peer['bitfield'], random_first_piece=True)
                    self.send_interested(sock, is_interested)
                if msg_id == 1:
                    if not self.request_pieces.empty():
                        current_piece_index = self.request_pieces.get()
                        self.start_request(sock, current_piece_index)
                    else:
                        done = True
            return True
        except Exception as e:
            if DEBUG:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                print(e)
                print('Lost connection to Peer...')
            return None
        finally:
            if not all(self.torrent.pieces_have) and current_piece_index is not None:
                self.request_pieces.put_nowait(current_piece_index)
            if sock:
                sock.close()

    def retry_pieces(self, piece_index, peerid):
        self.retry_counts[peerid][piece_index] += 1
        self.request_pieces.put_nowait(piece_index)
        if DEBUG:
            if self.retry_counts[peerid][piece_index] > self.max_retries:
                print(f"\nReached max retries for piece {piece_index}. Skipping.")
            else:
                print(f"\nRetrying piece {piece_index}. Attempt {self.retry_counts[peerid][piece_index]}")
        return self.retry_counts[peerid][piece_index] > self.max_retries
                
    def connect_to_peer(self, peer):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((peer['ip'], peer['port']))
            sock.settimeout(30)
            handshake_message = self.create_handshake_message()
            sock.sendall(handshake_message)
            response = sock.recv(68)
            if len(response) != 68:
                if DEBUG:
                    print("Failed to receive a proper handshake response.")
                sock.close()
                return None
            if response[:20] != handshake_message[:20]:
                if DEBUG:
                    print("Invalid handshake received. Closing connection.")
                sock.close()
                return None
            received_info_hash = response[28:48]
            received_peer_id = response[48:68]
            if received_info_hash.hex() != self.torrent.info_hash:
                if DEBUG:
                    print("Info hash mismatch. Closing connection.")
                sock.close()
                return None
            if received_peer_id.hex() != peer['peerid']:
                if DEBUG:
                    print("Connected wrong peer. Closing connection.")
                sock.close()
                return None
            if DEBUG:
                print(f"Connected to peer {peer['ip']}:{peer['port']}")
            return sock
        except Exception as e:
            if DEBUG:
                print(f"Failed to connect to peer {peer['ip']}:{peer['port']}: {e}")
            return None
             
    def handle_client(self, client_sock, client_addr, create_handshake_message):
        try:
            if DEBUG:
                print(f"Received connection from {client_addr}")
            handshake = client_sock.recv(68)
            if len(handshake) != 68:
                if DEBUG:
                    print("Invalid handshake received. Closing connection.")
                client_sock.close()
                return
            received_info_hash = handshake[28:48]
            if received_info_hash.hex() != self.torrent.info_hash:
                if DEBUG:
                    print("Info hash mismatch. Disconnecting.")
                client_sock.close()
                return
            response_handshake = create_handshake_message()
            client_sock.send(response_handshake)
            if DEBUG:
                print(f"Handshake successful with peer {client_addr}")
            bitfield_message = self.create_bitfield(self.torrent.pieces_have)
            self.send_message(client_sock, 5, bitfield_message)
            while not self.stop:
                msg_id, payload = self.receive_message(client_sock)
                if msg_id == 2:
                    self.aes_key[client_addr] = payload
                if DEBUG:
                    print(f"Received message ID {msg_id}")
                if msg_id is None:
                    break
                self.process_message(client_sock, msg_id, payload)
        except Exception as e:
            if DEBUG:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                print(e)
                print(f"Error occurred while handling client {client_addr}: {e}")
        finally:
            client_sock.close()

    def listen_for_handshake(self, port):
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.bind(('', port))
            server_sock.listen(5)
            if DEBUG:
                print(f"Listening for incoming connections on port {port}...")
            while not self.stop:
                client_sock, client_addr = server_sock.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_sock, client_addr, self.create_handshake_message)
                )
                client_thread.start()
        except Exception as e:
            if DEBUG:
                print(f"Error occurred while listening for handshakes: {e}")
        finally:
            server_sock.close()

    def start_server_in_thread(self, port):
        server_thread = threading.Thread(target=self.listen_for_handshake, args=(port,), daemon=True)
        server_thread.start()
        if DEBUG:
            print(f"Server started on port {port} in a separate thread.")


    def handle_request(self, sock, payload):
        piece_index, begin, length = struct.unpack("!III", payload)
        if DEBUG:
            print(f"Peer requested piece index: {piece_index}, begin: {begin}, length: {length}")
        if self.validate_request(piece_index, begin, length):
            self.send_piece(sock, piece_index, begin, length)
        else:
            if DEBUG:
                print("Invalid request. Ignoring.")

    def validate_request(self, piece_index, begin, length):
        num_pieces = len(self.torrent.pieces_have)
        if piece_index < 0 or piece_index >= num_pieces:
            return False
        if length <= 0 or length > block_size:
            return False
        total_file_size = self.torrent.total_length
        piece_length = self.torrent.piece_length
        piece_size = (total_file_size % piece_length) if piece_index == num_pieces - 1 else piece_length
        if piece_size == 0:
            piece_size = piece_length
        if begin < 0 or begin >= piece_size or begin + length > piece_size:
            return False
        return self.torrent.pieces_have[piece_index]

    def send_piece(self, sock, piece_index, begin, length):
        piece_data = self.get_piece_data(piece_index, begin, length)
        nonce = os.urandom(12)
        cipher = AESGCM(self.aes_key[sock.getpeername()])
        encrypted_data = cipher.encrypt(nonce, piece_data, None)
        encrypted_data = nonce + encrypted_data
        payload = struct.pack("!II", piece_index, begin) + encrypted_data
        self.send_message(sock, 7, payload)
        if DEBUG:
            print(f"Sent piece index: {piece_index}, begin: {begin}, length: {len(encrypted_data)}")

    def get_piece_data(self, piece_index, begin, length):
        byte_offset = piece_index * self.torrent.piece_length + begin
        remaining_length = length
        data = b''
        current_offset = 0
        def read_from_file(file_path, file_offset, read_length):
            with open(file_path, 'rb') as f:
                f.seek(file_offset)
                return f.read(read_length)         
        if not self.torrent.paths:
            file_path = os.path.join(self.torrent.name)
            with open(file_path, 'rb') as f:
                f.seek(byte_offset)
                data = f.read(length)
        else:
            read_tasks = []
            with ThreadPoolExecutor() as executor:
                for file_info in self.torrent.paths:
                    file_length = file_info['length']
                    file_path = os.path.join(self.torrent.name, *file_info['path'])
                    if current_offset <= byte_offset < current_offset + file_length:
                        file_offset = byte_offset - current_offset
                        read_length = min(remaining_length, file_length - file_offset)
                        read_tasks.append(executor.submit(read_from_file, file_path, file_offset, read_length))
                        remaining_length -= read_length
                        byte_offset += read_length
                        if remaining_length <= 0:
                            break
                    current_offset += file_length
                for task in read_tasks:
                    data += task.result()
        return data
    
    def write_piece_data(self, piece_index, data):
        byte_offset = piece_index * self.torrent.piece_length
        remaining_data = data
        current_offset = 0
        downloads_folder = os.path.join(downloads_dir, self.torrent.name)
        if not self.torrent.paths:
            file_path = os.path.join(downloads_folder)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            open_mode = 'r+b' if os.path.exists(file_path) else 'w+b'
            with open(file_path, open_mode) as f:
                f.seek(byte_offset)
                f.write(remaining_data)
        else:
            for file_info in self.torrent.paths:
                file_length = file_info['length']
                file_path = os.path.join(downloads_folder, *file_info['path'])
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                if current_offset <= byte_offset < current_offset + file_length:
                    file_offset = byte_offset - current_offset
                    open_mode = 'r+b' if os.path.exists(file_path) else 'w+b'
                    with open(file_path, open_mode) as f:
                        write_size = min(len(remaining_data), file_length - file_offset)
                        f.seek(file_offset)
                        f.write(remaining_data[:write_size])
                    remaining_data = remaining_data[write_size:]
                    byte_offset += write_size
                    if not remaining_data:
                        break
                current_offset += file_length

    def update_bitfield(self, sock, piece_index):
        peer_ip ,peer_port = sock.getpeername()
        for p in self.peers:
            if p['ip'] == peer_ip and p['port'] == peer_port:
                p['bitfield'][piece_index] = True
                break

    def start_request(self, sock, piece_index, begin=0):
        # if DEBUG: time.sleep(1)
        length = min(block_size, self.torrent.total_length - piece_index * self.torrent.piece_length - begin)
        payload = struct.pack("!III", piece_index, begin, length)
        self.send_message(sock, 6, payload)
        if DEBUG:
            print(f"Requested piece {piece_index} from peer.")

    def handle_piece(self, payload):
        piece_index = struct.unpack("!I", payload[:4])[0]
        begin = struct.unpack("!I", payload[4:8])[0]
        nonce = payload[8:20]
        encrypted_data = payload[20:]
        cipher = AESGCM(self.aes_key[0])
        try:
            block = cipher.decrypt(nonce, encrypted_data, None)
        except Exception as e:
            if DEBUG:
                print(f"Failed to decrypt piece {piece_index}: {e}")
            return None, None
        if DEBUG:
            print(f"Received piece for index {piece_index}, begin {begin}, length {len(block)} bytes")
        try:
            if self.store_piece_block(piece_index, begin, block):
                return True, True
            else:
                if piece_index < self.torrent.num_pieces - 1:
                    piece_length = self.torrent.piece_length
                else:
                    piece_length = self.torrent.total_length % self.torrent.piece_length
                    if piece_length == 0:
                        piece_length = self.torrent.piece_length
                if begin + len(block) == piece_length:
                    return True, False
                else:
                    return False, True
        except Exception as e:
            if DEBUG:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno)
                print(e)
            return None, None

    def store_piece_block(self, piece_index, begin, block):
        with self.lock:
            self.downloaded_block[piece_index][begin] = block
        is_piece_complete = self.is_piece_complete(piece_index)
        if is_piece_complete:
            return self.assemble_complete_piece(piece_index)           
        return is_piece_complete

    def is_piece_complete(self, piece_index):
        total_size = self.torrent.piece_length if piece_index < self.torrent.num_pieces - 1 else (self.torrent.total_length % self.torrent.piece_length or self.torrent.piece_length)
        num_blocks = (total_size + block_size - 1) // block_size
        if DEBUG:
            print(f"Piece {piece_index} has {len(self.downloaded_block[piece_index])} blocks out of {num_blocks}")
        return len(self.downloaded_block[piece_index]) == num_blocks

    def assemble_complete_piece(self, piece_index):
        blocks = self.downloaded_block[piece_index]
        complete_piece = b''.join(blocks[begin] for begin in sorted(blocks.keys()))     
        hash = hashlib.sha1(complete_piece).digest()
        if hash == self.torrent.piece_hashes[piece_index]:
            if DEBUG:
                print(f"Piece {piece_index} hash verified")
            self.write_piece_data(piece_index, complete_piece)
            if DEBUG:
                print(f"Piece {piece_index} fully downloaded and saved")
            self.downloaded_block[piece_index].clear()
            return True
        if DEBUG:        
            print(f"Piece {piece_index} hash verification failed")
        return False

    def ip_and_port_to_peer_id(self, ip, port):
        peer_ip = ip
        peer_port = port
        peer_id = None
        for p in self.peers:
            if p['ip'] == peer_ip and p['port'] == peer_port:
                peer_id = p['peerid']
                break
        return peer_id

    def verify_file_hash(self):
        print('Verifying hashes...')
        downloaded_info = create_info(os.path.join(downloads_dir, self.torrent.name))
        downloaded_info_hash = calculate_info_hash(downloaded_info)
        if downloaded_info_hash == self.torrent.info_hash:
            print('File hash verified')
            return True
        else:
            print('File hash verification failed')
            return False

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
        if DEBUG:
            print(data['path'])
    try:
        response = session.post(url, files=file, data=data)
        if response.status_code == 200:
                print("Torrent uploaded successfully")
        else:
                print("Failed to upload torrent:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())
    except requests.exceptions.ConnectionError:
        if DEBUG:
            print("Failed to connect to server")
    except Exception as e:
        if DEBUG:
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
        if DEBUG:
            print("Failed to connect to server")
    except Exception as e:
        if DEBUG:
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
        'event': event,
        'ip': '127.0.0.1' if server_url == 'http://127.0.0.1:8000' else socket.gethostbyname(socket.gethostname())
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
                # if peerid == peer_id:
                #     if peer_info['ip'] != public_ip:
                #         if DEBUG: print("Error from tracker.")
                #         # return None
                #         continue
                # peer_info['ip'] = socket.gethostbyname(socket.gethostname()) if server_url == 'http://127.0.0.1:8000' else '127.0.0.1'
                # peer_info['ip'] = public_ip
                peers_list.append(peer_info)
            return peers_list
        else:
            print("Failed to announce:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())
    except Exception as e:
        if DEBUG:
            print("An error occurred:", e)

def register(username_input, password_input):
    data = {'username': username_input, 'password': password_input}
    url = server_url + '/signup'
    response = session.post(url, json=data)
    if response.status_code == 200:
        print("Registration successful")
    else:
        print("Registration failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def login(username_input, password_input):
    data = {'username': username_input, 'password': password_input}
    url = server_url + '/login'
    response = session.post(url, json=data)
    if response.status_code == 200:
        print("Login successful")
        global username
        username = username_input
        return True
    else:
        print("Login failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())
        return False

def logout():
    url = server_url + '/logout'
    response = session.post(url)
    if response.status_code == 200:
        print("Logout successful")
    else:
        print("Logout failed:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())

def format_size(bytes_size):
    if bytes_size < 1024:
        return f"{bytes_size} B"
    elif bytes_size < 1024 ** 2:
        return f"{bytes_size / 1024:.2f} KB"
    elif bytes_size < 1024 ** 3:
        return f"{bytes_size / 1024 ** 2:.2f} MB"
    else:
        return f"{bytes_size / 1024 ** 3:.2f} GB"

def list_torrents():
    url = server_url + '/list_torrents'
    response = session.get(url)
    torrents_list = []
    if response.status_code == 200:
        torrents = bencodepy.decode(response.content)
        table_data = []
        for idx, (info_hash, torrent_info) in enumerate(torrents.items(), start=1):
            info_hash = info_hash.decode()
            torrent_info = {k.decode(): v for k, v in torrent_info.items()}
            name = torrent_info['name'].decode()
            uploaded_by = torrent_info.get('created_by', b'').decode()
            date_uploaded = time.ctime(torrent_info.get('date_uploaded', time.time()))
            seeder = torrent_info.get('seeder', 0)
            leecher = torrent_info.get('leecher', 0)
            completed = torrent_info.get('completed', 0)
            if 'file_size' in torrent_info:
                size = format_size(torrent_info['file_size'])
            else:
                size = 'Multiple files'
            table_data.append([idx, info_hash, name, size, uploaded_by, date_uploaded, seeder, leecher, completed])
            torrents_list.append({'info_hash': info_hash, 'name': name})
        headers = ['No.', 'Info Hash', 'Name', 'Size', 'Uploaded By', 'Date Uploaded', 'Seeders', 'Leechers', 'Completed']
        print(tabulate(table_data, headers=headers, tablefmt='grid'))
        return torrents_list
    else:
        print("Failed to get torrents:", bencodepy.decode(response.content).get(b'failure reason', b'').decode())
        return None

def start_as_seeder(torrent, peer_id, pieces=None):
    conn = Connection(torrent, peer_id)
    if pieces:
        conn.torrent.pieces_have = pieces.copy()
    peer_list = announce(conn.torrent.info_hash, event='started', port=peer_port)
    atexit.register(announce, conn.torrent.info_hash, event='stopped', port=peer_port)
    conn.peers = peer_list
    print(f"\nSeeder is ready to serve file '{conn.torrent.name}'.")
    conn.start_server_in_thread(peer_port)
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopping seeder...")
    finally:
        announce(conn.torrent.info_hash, event='stopped', port=peer_port)
        atexit.unregister(announce)
        print("Seeder stopped.")
        conn.stop = True

def start_as_leecher(torrent, peer_id, pieces=None):
    conn = Connection(torrent, peer_id)
    if pieces:
        conn.torrent.pieces_have = pieces.copy()
    conn.aes_key[0] = AESGCM.generate_key(bit_length=256)
    peer_list = announce(conn.torrent.info_hash, event='started', port=peer_port, uploaded=0, downloaded=0, left=conn.torrent.total_length)
    atexit.register(announce, conn.torrent.info_hash, event='stopped', port=peer_port)
    print(f"\nLeecher '{peer_id.hex()}' started downloading file '{conn.torrent.name}'.")
    try:
        conn.start_server_in_thread(peer_port)
        conn.run(peer_list)
    except KeyboardInterrupt:
        print("Stopping leecher...")
        conn.stop = True

    if all(conn.torrent.pieces_have):
        print(f"\nFile '{conn.torrent.name}' has been successfully saved.")
        announce(conn.torrent.info_hash, event='completed', port=peer_port)
        piece_history[torrent.info_hash] = conn.torrent.pieces_have
        atexit.unregister(announce)
    else:
        print("\nDownload incomplete.")
        piece_history[torrent.info_hash] = conn.torrent.pieces_have
        announce(conn.torrent.info_hash, event='stopped', port=peer_port)

def become_seeder():
    path = questionary.path("Enter the path to the file or directory to create a torrent:").ask()
    create_torrent(path, server_url)
    info = create_info(path)
    info_hash = calculate_info_hash(info)
    torrent_filename = info_hash + '.torrent'
    torrent_path = os.path.join(torrents_dir, torrent_filename)
    upload_torrent(torrent_path)
    print("Listening on port", peer_port)
    print("Peer ID:", peer_id)
    torrent = Torrent(torrent_path)
    piece_history[info_hash] = [True] * torrent.num_pieces
    pieces_have = piece_history[info_hash]
    start_as_seeder(torrent, bytes.fromhex(peer_id), pieces_have)

def become_leecher():
    torrents_list = list_torrents()
    if not torrents_list:
        print("No torrents available for download.")
        return
    while True:
        selection = input("Enter the number of the torrent to download: ")
        try:
            selection = int(selection)
            if 1 <= selection <= len(torrents_list):
                selected_torrent = torrents_list[selection - 1]
                break
            else:
                print("Invalid selection. Please enter a number from the list.")
        except ValueError:
            print("Invalid input. Please enter a number.")
    info_hash = selected_torrent['info_hash']
    torrent_filename = info_hash + '.torrent'
    torrent_path = os.path.join(torrents_dir, torrent_filename)
    if not os.path.exists(torrent_path):
        download_torrent(info_hash)
    print("Peer ID:", peer_id)
    torrent = Torrent(torrent_path)
    if not info_hash in piece_history or all(piece_history[info_hash]) or not any(piece_history[info_hash]):
        piece_history[info_hash] = [False] * torrent.num_pieces
    else:
        choice = questionary.select(
            "You have started downloading this file before. Continue last download?",
            choices=[
                "1. Yes",
                "2. No ",
                "Exit"
            ]).ask()
        if choice is None or choice == 'Exit':
            return
        if choice.startswith('1'):
            pass
        if choice.startswith('2'):
            piece_history[info_hash] = [False] * torrent.num_pieces
    pieces_have = piece_history[info_hash]
    start_as_leecher(torrent, bytes.fromhex(peer_id), pieces_have)

def settings_menu():
    global DEBUG, server_url
    while True:
        choice = questionary.select(
            "Settings:",
            choices=[
                "1. Toggle Debug Mode",
                "2. Change Server URL",
                "Back"
            ]).ask()
        if choice is None or choice == 'Back':
            break
        elif choice.startswith('1'):
            DEBUG = not DEBUG
            print(f"Debug mode is now {'on' if DEBUG else 'off'}")
        elif choice.startswith('2'):
            new_url = questionary.text("Enter new server URL:").ask()
            if new_url:
                server_url = new_url
                print(f"Server URL is now set to {server_url}")
            else:
                print("Server URL not changed.")
        else:
            print("Invalid choice")

if __name__ == '__main__':
    is_logged_in = False
    while True:
        if not is_logged_in:
            choice = questionary.select(
                "Select an option:",
                choices=[
                    "1. Register",
                    "2. Login",
                    "Exit"
                ]).ask()
        else:
            choice = questionary.select(
                "Select an option:",
                choices=[
                    "1. Become Seeder",
                    "2. Become Leecher",
                    "3. Settings",
                    "4. Logout",
                    "Exit"
                ]).ask()

        if choice is None or choice == 'Exit':
            break
        if not is_logged_in:
            if choice.startswith('1'):
                username_input = questionary.text("Enter username:").ask()
                password_input = questionary.password("Enter password:").ask()
                register(username_input, password_input)
            elif choice.startswith('2'):
                username_input = questionary.text("Enter username:").ask()
                password_input = questionary.password("Enter password:").ask()
                is_logged_in = login(username_input, password_input)
                if is_logged_in:
                    atexit.register(logout)
            else:
                print("Invalid choice")
        else:
            if choice.startswith('1'):
                become_seeder()
            elif choice.startswith('2'):
                become_leecher()
            elif choice.startswith('3'):
                settings_menu()
            elif choice.startswith('4'):
                logout()
                is_logged_in = False
                atexit.unregister(logout)
            else:
                print("Invalid choice")
            
