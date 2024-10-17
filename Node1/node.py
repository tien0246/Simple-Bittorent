import socket
import threading
import hashlib
import bencodepy
import json
import time
import os
import requests

PIECE_SIZE = 512 * 1024  # 512KB

class Peer:
    def __init__(self, ip, port, peer_id, node):
        self.ip = ip
        self.port = port
        self.peer_id = peer_id
        self.node = node
        self.socket = None
        self.handshake_done = False
        self.interested = False
        self.has_pieces = set()
        self.lock = threading.Lock()

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.ip, self.port))
            self.perform_handshake()
            threading.Thread(target=self.listen, daemon=True).start()
            self.request_pieces()
        except Exception as e:
            print(f"Kết nối thất bại với peer {self.ip}:{self.port} - {e}")

    def perform_handshake(self):
        pstr = b"BitTorrent protocol"
        pstrlen = len(pstr)
        reserved = b'\x00' * 8
        info_hash = self.node.info_hash_bytes
        peer_id = self.node.peer_id.encode()

        handshake = bytes([pstrlen]) + pstr + reserved + info_hash + peer_id
        self.socket.send(handshake)

        response = self.socket.recv(68)
        if response[:20] != handshake[:20]:
            raise Exception("Handshake không hợp lệ")
        self.handshake_done = True
        print(f"Hoàn thành handshake với peer {self.ip}:{self.port}")

    def listen(self):
        try:
            while True:
                data = self.socket.recv(4096)
                if not data:
                    break
                self.handle_message(data)
        except Exception as e:
            print(f"Kết nối bị mất với peer {self.ip}:{self.port} - {e}")
        finally:
            self.socket.close()

    def handle_message(self, data):
        # Xử lý tin nhắn nhận được từ peer
        # Cần triển khai theo giao thức BitTorrent
        pass

    def send_message(self, message):
        with self.lock:
            self.socket.send(message)

    def request_pieces(self):
        # Yêu cầu các piece cần tải
        # Cần triển khai logic yêu cầu piece theo giao thức BitTorrent
        pass

class TorrentCreator:
    def __init__(self, file_path, tracker_url, output_path, piece_size=512 * 1024):
        self.file_path = file_path
        self.tracker_url = tracker_url
        self.output_path = output_path
        self.piece_size = piece_size
        self.info = {}
        self.torrent = {}

    def create_torrent(self):
        if not os.path.exists(self.file_path):
            print("Tệp nguồn không tồn tại.")
            return False

        file_size = os.path.getsize(self.file_path)
        file_name = os.path.basename(self.file_path)

        # Tính toán các piece
        pieces = []
        with open(self.file_path, 'rb') as f:
            while True:
                piece = f.read(self.piece_size)
                if not piece:
                    break
                pieces.append(hashlib.sha1(piece).digest())

        pieces_concatenated = b''.join(pieces)

        # Tạo phần 'info'
        self.info = {
            b'name': file_name.encode(),
            b'length': file_size,
            b'piece length': self.piece_size,
            b'pieces': pieces_concatenated
        }

        # Tạo cấu trúc torrent
        self.torrent = {
            b'announce': self.tracker_url.encode(),
            b'info': self.info
        }

        # Ghi tệp torrent
        with open(self.output_path, 'wb') as f:
            f.write(bencodepy.encode(self.torrent))

        print(f"Tạo tệp torrent thành công: {self.output_path}")
        return True

class Node:
    def __init__(self, torrent_file=None):
        self.torrent_file = torrent_file
        self.tracker_url = None
        self.info_hash_bytes = None
        self.peer_id = self.generate_peer_id()
        self.peers = []
        self.pieces = []
        self.piece_length = PIECE_SIZE
        self.file_length = 0
        self.file_path = ''
        self.downloaded = 0
        self.lock = threading.Lock()
        self.piece_status = []
        self.info = {}
        if self.torrent_file:
            self.load_torrent()

    def load_torrent(self):
        with open(self.torrent_file, 'rb') as f:
            torrent_data = bencodepy.decode(f.read())

        # Lấy URL của tracker từ tệp torrent
        self.tracker_url = torrent_data.get(b'announce').decode()
        print(f"Tracker URL: {self.tracker_url}")

        # Lấy thông tin từ phần 'info'
        self.info = torrent_data[b'info']
        self.info_hash_bytes = hashlib.sha1(bencodepy.encode(self.info)).digest()
        self.file_length = self.info.get(b'length', 0)
        self.file_path = self.info.get(b'name', b'file').decode()
        pieces_raw = self.info.get(b'pieces', b'')
        self.pieces = [pieces_raw[i:i+20] for i in range(0, len(pieces_raw), 20)]
        print(f"Tên file: {self.file_path}, Kích thước: {self.file_length} bytes")

        # Khởi tạo trạng thái các piece
        self.piece_status = [False] * len(self.pieces)
        self.load_existing_file()

    def generate_peer_id(self):
        return f"-PC0001-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:12]}"

    def load_existing_file(self):
        if os.path.exists(self.file_path):
            existing_size = os.path.getsize(self.file_path)
            self.downloaded = existing_size
            # Ở đây bạn có thể kiểm tra các piece đã tải xuống
            print(f"Tìm thấy file tồn tại: {self.file_path}, Kích thước: {existing_size} bytes")
        else:
            # Tạo file trống
            with open(self.file_path, 'wb') as f:
                f.truncate(self.file_length)
            print(f"Tạo file mới: {self.file_path}")

    def announce_to_tracker(self):
        params = {
            'info_hash': self.info_hash_bytes.hex(),
            'peer_id': self.peer_id,
            'port': 6881,
            'uploaded': self.downloaded,
            'downloaded': self.downloaded,
            'left': self.file_length - self.downloaded,
            'event': 'started'
        }
        response = requests.get(f"{self.tracker_url}/announce", params=params)
        if response.status_code == 200:
            response_data = bencodepy.decode(response.content)
            peers_info = response_data.get(b'peers', {})
            for peer_id, peer in peers_info.items():
                ip = peer[b'ip'].decode()
                port = peer[b'port']
                peer_id_str = peer_id.decode()
                self.peers.append(Peer(ip, port, peer_id_str, self))
            print(f"Đã thông báo với tracker. Nhận được {len(self.peers)} peers.")
        else:
            print(f"Thông báo với tracker thất bại: {response.content}")

    def upload_torrent(self, name, file_size):
        params = {
            'info_hash': self.info_hash_bytes.hex(),
            'name': name,
            'file_size': file_size
        }
        response = requests.get(f"{self.tracker_url}/upload_torrent", params=params)
        if response.status_code == 200:
            print("Tải torrent lên tracker thành công.")
        else:
            print(f"Tải torrent lên tracker thất bại: {response.content}")

    def scrape(self, info_hash):
        params = {
            'info_hash': info_hash.hex()
        }
        response = requests.get(f"{self.tracker_url}/scrape", params=params)
        if response.status_code == 200:
            data = bencodepy.decode(response.content)
            print(f"Dữ liệu scrape: {data}")
        else:
            print(f"Scrape thất bại: {response.content}")

    def start(self):
        if not self.tracker_url:
            print("Không có URL tracker để thông báo.")
            return
        self.upload_torrent(self.file_path, self.file_length)
        self.announce_to_tracker()
        for peer in self.peers:
            threading.Thread(target=peer.connect, daemon=True).start()

    def download_piece(self, piece_index):
        # Triển khai logic tải xuống piece
        pass

    def upload_piece(self, piece_index, peer):
        # Triển khai logic tải lên piece cho peer
        pass

    @staticmethod
    def generate_info_hash(info):
        return hashlib.sha1(bencodepy.encode(info)).digest()

def interactive_menu():
    while True:
        print("\n===== BitTorrent Client Menu =====")
        print("1. Tạo tệp Torrent")
        print("2. Gửi Torrent lên Tracker để trở thành Seeder")
        print("3. Thoát")
        choice = input("Nhập lựa chọn của bạn (1/2/3): ")

        if choice == '1':
            create_torrent_flow()
        elif choice == '2':
            upload_torrent_flow()
        elif choice == '3':
            print("Thoát chương trình.")
            break
        else:
            print("Lựa chọn không hợp lệ. Vui lòng thử lại.")

def create_torrent_flow():
    file_path = input("Nhập đường dẫn tới tệp muốn chia sẻ: ").strip()
    tracker_url = input("Nhập URL của Tracker: ").strip()
    output_path = input("Nhập tên tệp torrent đầu ra (ví dụ: myfile.torrent): ").strip()

    creator = TorrentCreator(file_path, tracker_url, output_path)
    if creator.create_torrent():
        print(f"Tệp torrent đã được tạo tại: {output_path}")
    else:
        print("Tạo tệp torrent thất bại.")

def upload_torrent_flow():
    torrent_path = input("Nhập đường dẫn tới tệp torrent (.torrent): ").strip()
    if not os.path.exists(torrent_path):
        print("Tệp torrent không tồn tại.")
        return

    node = Node(torrent_path)
    node.start()

    # Giữ cho chương trình chạy
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        print("Dừng chương trình.")

if __name__ == "__main__":
    interactive_menu()
