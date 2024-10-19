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
    def __init__(self, info_hash, client_peer_id, pieces, num_pieces):
        self.info_hash = info_hash
        self.client_peer_id = client_peer_id
        self.pieces = pieces
        self.request_pieces = []
        self.num_pieces = num_pieces
        self.lock = threading.Lock()
        self.peers = {}

    def send_message(self, sock, msg_id, payload=b''):
        length = 1 + len(payload)
        message = struct.pack("!I", length) + struct.pack("!B", msg_id) + payload
        with self.lock:
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
            print("Failed to receive message:", e)
            return None, None

    def create_handshake_message(self):
        pstr = b"BitTorrent protocol"
        pstrlen = len(pstr)
        reserved = b'\x00' * 8
        handshake = struct.pack("!B", pstrlen) + pstr + reserved + self.info_hash + self.client_peer_id
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
    
    def send_interested(self, sock, have_pieces):
        interested = False
        self.request_pieces = []
        for i in range(self.num_pieces):
            if not self.pieces[i] and have_pieces[i]:
                interested = True
                print(i)
                self.request_pieces.append(i)
                break
        if interested:
            self.send_message(sock, 2)
            print("Sent Interested")
        else:
            self.send_message(sock, 3)
            print("Sent Not Interested")
    
    def process_message(self, sock, msg_id, payload):
        if msg_id == 0:
            pass
        elif msg_id == 1:
            print("Unchoke")
            self.request_next_piece(sock)
        elif msg_id == 2:
            print("Interested")
            self.send_message(sock, 1)
        elif msg_id == 3:
            print("Not interested")
            sock.close()
        elif msg_id == 4:
            print("Have")
        elif msg_id == 5:
            print("Bitfield")
            have_pieces = self.parse_bitfield(payload, self.num_pieces)
            self.send_interested(sock, have_pieces)
        elif msg_id == 6:
            print("Request")
            self.handle_request(sock, payload)
        elif msg_id == 7:
            print("Piece")
            self.request_next_piece(sock)
        elif msg_id == 8:
            print("Cancel")
        elif msg_id == 9:
            print("Port")
        else:
            print("Unknown message ID")


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

    def run(self, peer_list):
        threads = []
        for peer_ip, peer_port, peer_id in peer_list:
            thread = threading.Thread(target=self.handle_peer_connection, args=(peer_ip, peer_port, peer_id))
            thread.start()
            threads.append(thread)

        # Optional: Join all threads to ensure they complete
        for thread in threads:
            thread.join()
    def handle_peer_connection(self, peer_ip, peer_port, peer_id):
        try:
            sock = self.connect_to_peer(peer_ip, peer_port, peer_id)
            if not sock:
                return

            while True:
                msg_id, payload = self.receive_message(sock)
                if msg_id is None:
                    break
                self.process_message(sock, msg_id, payload)

        except Exception as e:
            print(f"Error handling peer connection: {e}")
        finally:
            if sock:
                sock.close()
        
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

            bitfield_message = self.create_bitfield(self.pieces)
            self.send_message(client_sock, 5, bitfield_message)

            while True:
                msg_id, payload = self.receive_message(client_sock)
                print(f"Received message ID {msg_id}")
                if msg_id is None:
                    break
                self.process_message(client_sock, msg_id, payload)

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

    def handle_request(self, sock, payload):
        # Parse the payload to extract index, begin, and length
        piece_index, begin, length = struct.unpack("!III", payload)
        print(f"Peer requested piece index: {piece_index}, begin: {begin}, length: {length}")

        # Validate the request
        if self.validate_request(piece_index, begin, length):
            # Send the requested piece data
            print('here')
            self.send_piece(sock, piece_index, begin, length)
        else:
            print("Invalid request. Ignoring.")

    def validate_request(self, piece_index, begin, length):
        # Example validation logic:
        # Ensure piece_index is valid and we have the requested piece
        if piece_index < 0 or piece_index >= len(self.pieces):
            return False

        # Ensure the requested data length is reasonable
        max_length = 16384  # Common max length (16KB)
        if length <= 0 or length > max_length:
            return False

        # Check if we actually have this piece
        return self.pieces[piece_index]

    def send_piece(self, sock, piece_index, begin, length):
        # Fetch the data to be sent
        piece_data = self.get_piece_data(piece_index, begin, length)

        # Construct the piece message (ID = 7)
        msg_id = 7
        message = struct.pack("!IBIII", len(piece_data) + 9, msg_id, piece_index, begin, piece_data)
        self.send_message(sock, message)

        print(f"Sent piece index: {piece_index}, begin: {begin}, length: {len(piece_data)}")

    def get_piece_data(self, piece_index, begin, length):
        # Fetch the piece data from disk or memory, starting at 'begin' with 'length' bytes
        return self.pieces[piece_index][begin:begin + length]
    
    def request_next_piece(self, sock):
        """
        Request the next piece from the list of pieces we need.
        """
        if not self.request_pieces:
            print("No pieces left to request.")
            return
        piece_index = self.request_pieces.pop(0)  # Get the next piece to request
        begin = 0  # Usually, you start from offset 0
        length = min(16384, self.num_pieces - begin)  # Request up to 16KB at a time

        # Construct the request message (ID = 6)
        payload = struct.pack("!III", piece_index, begin, length)
        self.send_message(sock, 6, payload)
        print(f"Requested piece {piece_index} from peer.")

    def handle_piece(self, payload):
        # The Piece message has the following structure:
        # <index (4 bytes)> <begin (4 bytes)> <block (N bytes)>
        piece_index = struct.unpack("!I", payload[:4])[0]
        begin = struct.unpack("!I", payload[4:8])[0]
        block = payload[8:]

        print(f"Received piece for index {piece_index}, begin {begin}, length {len(block)} bytes")

        # Store the block in the appropriate location
        self.store_piece_block(piece_index, begin, block)

    def store_piece_block(self, piece_index, begin, block):
        # Ensure that we have a structure to keep track of downloaded blocks
        if piece_index not in self.downloaded_pieces:
            self.downloaded_pieces[piece_index] = {}

        # Store the block using the `begin` offset as the key
        self.downloaded_pieces[piece_index][begin] = block

        # Check if we have all blocks for the piece
        if self.is_piece_complete(piece_index):
            self.assemble_complete_piece(piece_index)

    def is_piece_complete(self, piece_index):
        # Check if all blocks of a particular piece are downloaded
        # Assuming fixed block size for simplicity, you may need to adjust this for different protocols
        total_size = self.piece_length[piece_index]
        block_size = 16384  # Default block size in bytes (16 KB)

        # Calculate expected number of blocks
        num_blocks = (total_size + block_size - 1) // block_size

        # Ensure we have received all blocks
        return len(self.downloaded_pieces[piece_index]) == num_blocks

    def assemble_complete_piece(self, piece_index):
        # Assemble all blocks into a complete piece
        blocks = self.downloaded_pieces[piece_index]
        complete_piece = b''.join(blocks[begin] for begin in sorted(blocks.keys()))

        # Save the complete piece to disk or add it to the in-memory cache
        self.save_complete_piece(piece_index, complete_piece)

        # Mark the piece as fully downloaded
        print(f"Piece {piece_index} fully downloaded and saved")

        # Remove the blocks from the tracking data
        del self.downloaded_pieces[piece_index]

    def save_complete_piece(self, piece_index, complete_piece):
        # Example function to save a complete piece to disk
        # Implement this to suit your storage mechanism
        file_name = f"piece_{piece_index}.dat"
        with open(file_name, "wb") as file:
            file.write(complete_piece)
        print(f"Piece {piece_index} saved to {file_name}")

    def run(self):
        peer_ip = '10.0.247.157'
        peer_port = 9001
        peer_id = bytes.fromhex(input("Enter peer ID: "))
        self.handle_peer_connection(peer_ip, peer_port, peer_id)
    

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
                connect = Connection(info_hash, bytes.fromhex(peer_id), [False] * 10, 10)
                connect.run()
            elif choice == '10':
                # port = int(input("Enter peer port: "))
                port = 9001
                print("Listening on port", port)
                print("Peer ID:", peer_id)
                # info_hash = bytes.fromhex(input("Enter info hash (hex): "))
                info_hash = bytes.fromhex('95acaa0905b98ea184ea9bd2d7c2c916421cbd4c')
                peerid = bytes.fromhex(peer_id)
                connect = Connection(info_hash, peerid, [True] * 10, 10)
                # connect.listen_for_handshake(port)
                connect.start_server_in_thread(port)
            else:
                print("Invalid choice")
    except KeyboardInterrupt:
        announce("95acaa0905b98ea184ea9bd2d7c2c916421cbd4c", "stopped", 9001, 0, 0, 100)