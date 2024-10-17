import requests
import hashlib
import json
import bencodepy
import os
import threading
import socket
import getpass  # Securely input username
import time

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
    def __init__(self, file_paths, tracker_url, output_path, piece_size=512 * 1024, created_by=""):
        """
        file_paths: danh sách các đường dẫn tới các tệp hoặc thư mục cần chia sẻ
        tracker_url: URL của Tracker
        output_path: Đường dẫn tới tệp torrent đầu ra
        piece_size: Kích thước mỗi piece (mặc định 512KB)
        """
        self.file_paths = file_paths
        self.tracker_url = tracker_url
        self.output_path = output_path
        self.piece_size = piece_size
        self.created_by = created_by  # Lưu lại tên người dùng đăng nhập
        self.info = {}
        self.torrent = {}

    def create_torrent(self):
        # Kiểm tra tồn tại của tất cả các tệp
        for path in self.file_paths:
            if not os.path.exists(path):
                print(f"Tệp nguồn không tồn tại: {path}")
                return False

        # Xử lý multi-file torrent
        if len(self.file_paths) == 1 and os.path.isfile(self.file_paths[0]):
            # Single-file torrent
            file_path = self.file_paths[0]
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            # Tính toán các piece
            pieces = []
            with open(file_path, 'rb') as f:
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
        else:
            # Multi-file torrent
            files = []
            total_length = 0
            common_path = os.path.commonpath(self.file_paths)
            all_files = self._gather_all_files(common_path)
            for path in all_files:
                file_size = os.path.getsize(path)
                file_relative_path = os.path.relpath(path, common_path)
                files.append({
                    b'length': file_size,
                    b'path': file_relative_path.replace('\\', '/').encode().split(b'/')
                })
                total_length += file_size

            # Tính toán các piece cho multi-file torrent
            pieces = []
            buffer = b''
            sha1 = hashlib.sha1()

            for path in all_files:
                with open(path, 'rb') as f:
                    while True:
                        data = f.read(65536)  # Đọc theo khối 64KB để tối ưu
                        if not data:
                            break
                        buffer += data
                        while len(buffer) >= self.piece_size:
                            piece_data = buffer[:self.piece_size]
                            buffer = buffer[self.piece_size:]
                            sha1.update(piece_data)
                            pieces.append(sha1.digest())
                            sha1 = hashlib.sha1()
            # Xử lý phần dư
            if buffer:
                sha1.update(buffer)
                pieces.append(sha1.digest())

            pieces_concatenated = b''.join(pieces)

            # Tạo phần 'info'
            self.info = {
                b'name': os.path.basename(common_path).encode(),
                b'piece length': self.piece_size,
                b'pieces': pieces_concatenated,
                b'files': files
            }

        # Thêm trường 'creation date' và 'created by'
        creation_date = int(time.time())

        # Tạo cấu trúc torrent
        self.torrent = {
            b'announce': self.tracker_url.encode(),
            b'creation date': creation_date,
            b'created by': self.created_by.encode(),
            b'info': self.info
        }

        # Ghi tệp torrent
        with open(self.output_path, 'wb') as f:
            f.write(bencodepy.encode(self.torrent))

        print(f"Tạo tệp torrent thành công: {self.output_path}")
        return True

    def _gather_all_files(self, common_path):
        """
        Thu thập tất cả các tệp trong danh sách file_paths dựa trên common_path.
        """
        all_files = []
        for path in self.file_paths:
            if os.path.isfile(path):
                all_files.append(path)
            elif os.path.isdir(path):
                for root, dirs, filenames in os.walk(path):
                    for filename in filenames:
                        full_path = os.path.join(root, filename)
                        all_files.append(full_path)
        return all_files

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
        self.username = None
        self.password = None
        self.session = requests.Session()  # Use a session to persist cookies

        if self.torrent_file:
            self.load_torrent()

    def signup(self, tracker_url):
        self.tracker_url = tracker_url
        self.username = input("Enter username: ").strip()
        self.password = getpass.getpass("Enter password: ").strip()

        data = {
            'username': self.username,
            'password': self.password
        }

        response = self.session.post(f"{self.tracker_url}/signup", json=data)

        if response.status_code == 200:
            print("Signup successful! You can now log in.")
        else:
            print(f"Signup failed: {response.content.decode()}")

    def login(self, tracker_url):
        self.tracker_url = tracker_url
        self.username = input("Enter username: ").strip()
        self.password = input("Enter password: ").strip()

        data = {
            'username': self.username,
            'password': self.password
        }

        response = self.session.post(f"{self.tracker_url}/login", json=data)

        if response.status_code == 200:
            print("Login successful!")
        else:
            print(f"Login failed: {response.content.decode()}")
            self.username = None

    def logout(self):
        response = self.session.post(f"{self.tracker_url}/logout")
        if response.status_code == 200:
            print("Logout successful!")
        else:
            print(f"Logout failed: {response.content.decode()}")

    def announce_to_tracker(self):
        left = self.file_length - self.downloaded if 'length' in self.info else 0
        params = {
            'info_hash': self.info_hash_bytes.hex(),
            'peer_id': self.peer_id,
            'port': 6881,
            'uploaded': self.downloaded,
            'downloaded': self.downloaded,
            'left': left,
            'event': 'started'
        }
        response = self.session.get(f"{self.tracker_url}/announce", params=params)
        if response.status_code == 200:
            response_data = bencodepy.decode(response.content)
            peers_info = response_data.get(b'peers', {})
            for peer_id, peer in peers_info.items():
                ip = peer[b'ip'].decode()
                port = peer[b'port']
                peer_id_str = peer_id.decode()
                self.peers.append(Peer(ip, port, peer_id_str, self))
            print(f"Announced to tracker. Received {len(self.peers)} peers.")
        else:
            print(f"Announce failed: {response.content}")

    def load_torrent(self):
        with open(self.torrent_file, 'rb') as f:
            torrent_data = bencodepy.decode(f.read())

        # Lấy URL của tracker từ tệp torrent
        self.tracker_url = torrent_data.get(b'announce').decode()
        print(f"Tracker URL: {self.tracker_url}")

        # Lấy thông tin từ phần 'info'
        self.info = torrent_data[b'info']
        self.info_hash_bytes = hashlib.sha1(bencodepy.encode(self.info)).digest()
        self.file_length = self.info.get(b'length', 0)  # Chỉ sử dụng trong single-file torrent
        self.file_path = self.info.get(b'name', b'file').decode()
        pieces_raw = self.info.get(b'pieces', b'')
        self.pieces = [pieces_raw[i:i+20] for i in range(0, len(pieces_raw), 20)]
        print(f"Tên torrent: {self.file_path}, Số lượng pieces: {len(self.pieces)}")

        # Khởi tạo trạng thái các piece
        self.piece_status = [False] * len(self.pieces)
        self.load_existing_file()

    def generate_peer_id(self):
        return f"-PC0001-{hashlib.sha1(str(time.time()).encode()).hexdigest()[:12]}"

    def load_existing_file(self):
        if 'files' in self.info:
            # Multi-file torrent
            if not os.path.exists(self.file_path):
                os.makedirs(self.file_path)
            for file in self.info[b'files']:
                file_rel_path = os.path.join(self.file_path, *[p.decode() for p in file[b'path']])
                file_dir = os.path.dirname(file_rel_path)
                if not os.path.exists(file_dir):
                    os.makedirs(file_dir)
                if not os.path.exists(file_rel_path):
                    with open(file_rel_path, 'wb') as f:
                        f.truncate(file[b'length'])
            print(f"Tạo thư mục và tệp mới cho multi-file torrent: {self.file_path}")
        else:
            # Single-file torrent
            if os.path.exists(self.file_path):
                existing_size = os.path.getsize(self.file_path)
                self.downloaded = existing_size
                print(f"Tìm thấy file tồn tại: {self.file_path}, Kích thước: {existing_size} bytes")
            else:
                with open(self.file_path, 'wb') as f:
                    f.truncate(self.file_length)
                print(f"Tạo file mới: {self.file_path}")

    # def announce_to_tracker(self):
    #     left = self.file_length - self.downloaded if 'length' in self.info else 0
    #     params = {
    #         'info_hash': self.info_hash_bytes.hex(),
    #         'peer_id': self.peer_id,
    #         'port': 6881,
    #         'uploaded': self.downloaded,
    #         'downloaded': self.downloaded,
    #         'left': left,
    #         'event': 'started'
    #     }
    #     response = requests.get(f"http://{self.tracker_url}/announce", params=params)
    #     if response.status_code == 200:
    #         response_data = bencodepy.decode(response.content)
    #         peers_info = response_data.get(b'peers', {})
    #         for peer_id, peer in peers_info.items():
    #             ip = peer[b'ip'].decode()
    #             port = peer[b'port']
    #             peer_id_str = peer_id.decode()
    #             self.peers.append(Peer(ip, port, peer_id_str, self))
    #         print(f"Đã thông báo với tracker. Nhận được {len(self.peers)} peers.")
    #     else:
    #         print(f"Thông báo với tracker thất bại: {response.content}")

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
    node = Node()
    while True:
        print("\n===== BitTorrent Client Menu =====")
        print("1. Sign Up")
        print("2. Log In")
        print("3. Create Torrent")
        print("4. Upload Torrent to Tracker to Become Seeder")
        print("5. Log Out")
        print("6. Exit")
        choice = input("Enter your choice (1-6): ")

        if choice == '1':
            tracker_url = input("Enter the Tracker URL (including http:// or https://): ").strip()
            if not tracker_url.startswith('http://') and not tracker_url.startswith('https://'):
                tracker_url = 'http://' + tracker_url
            node.signup(tracker_url)
        elif choice == '2':
            tracker_url = input("Enter the Tracker URL (including http:// or https://): ").strip()
            if not tracker_url.startswith('http://') and not tracker_url.startswith('https://'):
                tracker_url = 'http://' + tracker_url
            node.login(tracker_url)
        elif choice == '3':
            create_torrent_flow(node.username)
        elif choice == '4':
            upload_torrent_flow()
        elif choice == '5':
            node.logout()
        elif choice == '6':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please try again.")

def create_torrent_flow(username):
    print("\n=== Tạo Tệp Torrent ===")
    try:
        num_files = int(input("Bạn muốn chia sẻ bao nhiêu tệp/thư mục? Nhập số lượng: "))
    except ValueError:
        print("Vui lòng nhập một số hợp lệ.")
        return

    file_paths = []
    for i in range(num_files):
        path = input(f"Nhập đường dẫn tới tệp/thư mục {i+1}: ").strip()
        file_paths.append(path)

    tracker_url = input("Nhập URL của Tracker (bao gồm http:// hoặc https://): ").strip()
    if not tracker_url.startswith('http://') and not tracker_url.startswith('https://'):
        tracker_url = 'http://' + tracker_url  # Thêm http:// nếu người dùng chưa nhập

    output_path = input("Nhập tên tệp torrent đầu ra (ví dụ: myfile.torrent): ").strip()

    # Sử dụng đối tượng Node để lấy tên người dùng
    if not username:
        print("Bạn cần đăng nhập trước khi tạo tệp torrent.")
        return

    creator = TorrentCreator(file_paths, tracker_url, output_path, created_by=username)
    if creator.create_torrent():
        print(f"Tệp torrent đã được tạo tại: {output_path}")
    else:
        print("Tạo tệp torrent thất bại.")


def upload_torrent_flow():
    print("\n=== Gửi Torrent lên Tracker để trở thành Seeder ===")
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
