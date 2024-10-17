# node.py
import requests
import json
import os
import socket
import threading
import hashlib
import time
import sys
import struct
from concurrent.futures import ThreadPoolExecutor
from queue import Queue

TRACKER_URL = 'http://10.229.2.59:8000'  # Địa chỉ Tracker

class TrackerClient:
    def __init__(self, tracker_url):
        self.tracker_url = tracker_url

    def upload_torrent(self, torrent_path, info_hash):
        url = f"{self.tracker_url}/upload_torrent"
        files = {'torrent': open(torrent_path, 'rb')}
        data = {'info_hash': info_hash}
        try:
            response = requests.post(url, files=files, data=data)
            return response.json()
        except Exception as e:
            print(f"Error uploading torrent: {e}")
            return {'status': 'fail', 'message': str(e)}

    def list_torrents(self):
        url = f"{self.tracker_url}/list_torrents"
        try:
            response = requests.get(url)
            return response.json().get('torrents', [])
        except Exception as e:
            print(f"Error fetching torrent list: {e}")
            return []

    def download_torrent(self, filename, save_path):
        url = f"{self.tracker_url}/torrents/{filename}"
        try:
            response = requests.get(url, stream=True)
            if response.status_code == 200:
                with open(save_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=4096):
                        if chunk:
                            f.write(chunk)
                print(f"Tệp torrent đã được tải xuống và lưu tại: {save_path}")
                return True
            else:
                print(f"Không thể tải xuống tệp torrent: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"Error downloading torrent: {e}")
            return False

    def check_hash(self, info_hash):
        url = f"{self.tracker_url}/check_hash"
        params = {'info_hash': info_hash}
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json().get('exists', False)
            else:
                print(f"Tracker responded with status code {response.status_code}")
                return False
        except Exception as e:
            print(f"Error checking hash with tracker: {e}")
            return False

    def announce(self, info_hash, peer_id, port, event='started'):
        url = f"{self.tracker_url}/announce"
        params = {
            'info_hash': info_hash,
            'peer_id': peer_id,
            'port': port,
            'event': event
        }
        try:
            response = requests.get(url, params=params)
            if response.status_code == 200:
                return response.json().get('peers', [])
            else:
                print(f"Tracker responded with status code {response.status_code}")
                return []
        except Exception as e:
            print(f"Error announcing to tracker: {e}")
            return []

class TorrentClient:
    def __init__(self, peer_id, port, tracker_client, max_connections=5, max_retries=3):
        self.peer_id = peer_id
        self.port = port
        self.tracker = tracker_client
        self.max_connections = max_connections
        self.max_retries = max_retries

        # Các biến để quản lý torrent
        self.metainfo = {}
        self.file = ''
        self.file_size = 0
        self.piece_length = 0
        self.pieces = []
        self.overall_hash = ''
        self.info_hash = ''  # Thêm thuộc tính info_hash
        self.total_pieces = 0
        self.downloaded = []
        self.downloaded_pieces = 0
        self.retry_counts = []
        self.lock = threading.Lock()
        self.is_seeder = False
        self.file_handle = None
        self.piece_queue = Queue()

    def create_metainfo(self, file_path):
        """Tạo metainfo từ tệp và lưu vào tệp .torrent"""
        piece_length = 1024 * 1024  # 1MB mỗi piece
        file_size = os.path.getsize(file_path)
        pieces = []
        overall_hash = hashlib.sha1()

        with open(file_path, 'rb') as f:
            while True:
                piece = f.read(piece_length)
                if not piece:
                    break
                piece_hash = hashlib.sha1(piece).hexdigest()
                pieces.append(piece_hash)
                overall_hash.update(piece)

        metainfo = {
            "tracker": f"{TRACKER_URL}/announce",
            "file": os.path.basename(file_path),
            "file_size": file_size,
            "piece_length": piece_length,
            "pieces": pieces,
            "overall_hash": overall_hash.hexdigest()
        }

        # Tính toán info_hash bằng cách hash của JSON metainfo đã sắp xếp
        self.info_hash = hashlib.sha1(json.dumps(metainfo, sort_keys=True).encode()).hexdigest()

        # Đảm bảo thư mục 'torrents/' tồn tại
        if not os.path.exists('torrents'):
            os.makedirs('torrents')

        torrent_filename = os.path.join('torrents', f"{os.path.basename(file_path)}.torrent")
        with open(torrent_filename, 'w') as f:
            json.dump(metainfo, f)
        print(f"Metainfo file created: {torrent_filename}")
        return torrent_filename

    def select_torrent(self):
        """Chọn tệp torrent từ danh sách trên Tracker"""
        torrents = self.tracker.list_torrents()
        if not torrents:
            print("Không có tệp torrent nào được lưu trên Tracker.")
            return None

        print("\n===== Danh Sách Tệp Torrent Trên Tracker =====")
        for idx, torrent in enumerate(torrents, 1):
            print(f"{idx}. {torrent}")
        print("==============================================\n")

        while True:
            try:
                choice = int(input("Nhập số thứ tự của tệp torrent bạn muốn tải xuống: "))
                if 1 <= choice <= len(torrents):
                    selected_torrent = torrents[choice - 1]
                    # Tạo đường dẫn lưu trữ tệp torrent trên Node
                    local_torrent_path = os.path.join('torrents', selected_torrent)
                    # Đảm bảo thư mục 'torrents/' tồn tại
                    if not os.path.exists('torrents'):
                        os.makedirs('torrents')
                    # Tải xuống tệp torrent từ Tracker
                    success = self.tracker.download_torrent(selected_torrent, local_torrent_path)
                    if success:
                        return local_torrent_path
                    else:
                        print("Tải xuống tệp torrent thất bại. Vui lòng thử lại.")
                        return None
                else:
                    print("Lựa chọn không hợp lệ. Vui lòng thử lại.")
            except ValueError:
                print("Vui lòng nhập một số hợp lệ.")

    def load_metainfo(self, torrent_path):
        """Tải metainfo từ tệp torrent"""
        try:
            with open(torrent_path, 'r') as f:
                self.metainfo = json.load(f)
            self.file = self.metainfo['file']
            self.file_size = self.metainfo['file_size']
            self.piece_length = self.metainfo['piece_length']
            self.pieces = self.metainfo['pieces']
            self.overall_hash = self.metainfo.get('overall_hash', '')
            self.total_pieces = len(self.pieces)
            self.downloaded = [False] * self.total_pieces
            self.retry_counts = [0] * self.total_pieces
            for i in range(self.total_pieces):
                self.piece_queue.put(i)
            # Tính toán info_hash sau khi tải metainfo
            self.info_hash = hashlib.sha1(json.dumps(self.metainfo, sort_keys=True).encode()).hexdigest()
            print(f"Metainfo loaded từ {torrent_path}")
        except Exception as e:
            print(f"Lỗi khi tải metainfo: {e}")

    def compute_file_hash(self):
        """Tính toán mã băm SHA1 tổng thể của tệp."""
        sha1 = hashlib.sha1()
        try:
            with open(self.file, 'rb') as f:
                while True:
                    data = f.read(self.piece_length)
                    if not data:
                        break
                    sha1.update(data)
            return sha1.hexdigest()
        except Exception as e:
            print(f"Lỗi khi tính toán mã băm của tệp: {e}")
            return ''

    def start_seeder(self):
        """Khởi động chế độ Seeder"""
        self.is_seeder = True
        self.downloaded = [True] * self.total_pieces
        self.downloaded_pieces = self.total_pieces
        try:
            self.file_handle = open(self.file, 'rb')
        except Exception as e:
            print(f"Lỗi khi mở tệp để Seeder: {e}")
            return

        # Thông báo 'started' tới Tracker
        self.tracker.announce(self.info_hash, self.peer_id, self.port, event='started')

        print(f"\nSeeder '{self.peer_id}' đã sẵn sàng phục vụ tệp '{self.file}'.")
        threading.Thread(target=self.listen, daemon=True).start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            # Thông báo 'stopped' tới Tracker khi dừng Seeder
            self.tracker.announce(self.info_hash, self.peer_id, self.port, event='stopped')
            print("\nSeeder đã dừng.")
            self.file_handle.close()

    def start_leecher(self):
        """Khởi động chế độ Leecher"""
        try:
            self.file_handle = open(self.file, 'wb+')
        except Exception as e:
            print(f"Lỗi khi mở tệp để Leecher: {e}")
            return

        # Thông báo 'started' tới Tracker
        self.tracker.announce(self.info_hash, self.peer_id, self.port, event='started')

        print(f"\nLeecher '{self.peer_id}' bắt đầu tải xuống tệp '{self.file}'.")
        threading.Thread(target=self.listen, daemon=True).start()
        self.download()
        # Thông báo 'stopped' tới Tracker khi hoàn tất tải xuống
        self.tracker.announce(self.info_hash, self.peer_id, self.port, event='stopped')
        self.file_handle.close()
        if all(self.downloaded):
            print(f"\nFile '{self.file}' đã được lưu thành công.")
            self.verify_file_hash()
        else:
            print("\nTải xuống chưa hoàn thành.")

    def listen(self):
        """Nghe các kết nối từ các Leecher khác (nếu Seeder)"""
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('', self.port))
        s.listen(5)
        print(f"Listening on port {self.port} for incoming connections...")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=self.handle_peer, args=(conn, addr), daemon=True).start()

    def handle_peer(self, conn, addr):
        """Xử lý yêu cầu từ peer"""
        try:
            request = conn.recv(4)
            if len(request) < 4:
                conn.close()
                return
            piece_index = struct.unpack('!I', request)[0]
            if 0 <= piece_index < self.total_pieces:
                with self.lock:
                    self.file_handle.seek(piece_index * self.piece_length)
                    piece = self.file_handle.read(self.piece_length)
                piece_length_sent = struct.pack('!I', len(piece))
                conn.sendall(piece_length_sent)
                conn.sendall(piece)
        except Exception as e:
            print(f"Error handling peer {addr}: {e}")
        finally:
            conn.close()

    def download(self):
        """Quản lý quá trình tải xuống các piece"""
        with ThreadPoolExecutor(max_workers=self.max_connections) as executor:
            while not self.piece_queue.empty():
                peers = self.tracker.announce(self.info_hash, self.peer_id, self.port)
                # Lọc bỏ peer là chính mình
                peers = [peer for peer in peers if peer.get('peer_id') != self.peer_id and not (peer['ip'] == '127.0.0.1' and peer['port'] == self.port)]
                if not peers:
                    print("Không có peers nào để kết nối. Đang chờ...")
                    time.sleep(5)
                    continue
                for peer in peers:
                    if self.piece_queue.empty():
                        break
                    piece_index = self.piece_queue.get_nowait()
                    executor.submit(self.download_piece, peer, piece_index)
            executor.shutdown(wait=True)

    def download_piece(self, peer, piece_index):
        """Tải xuống một piece từ một peer"""
        ip = peer['ip']
        port = peer['port']
        peer_id = peer.get('peer_id', '')

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((ip, port))

            request = struct.pack('!I', piece_index)
            s.sendall(request)

            length_data = self.recvall(s, 4)
            if not length_data:
                print(f"\nKhông nhận được độ dài của piece {piece_index} từ {ip}:{port}")
                self.retry_piece(piece_index)
                s.close()
                return

            piece_length = struct.unpack('!I', length_data)[0]
            data = self.recvall(s, piece_length)
            if data:
                piece_hash = hashlib.sha1(data).hexdigest()
                if piece_hash == self.pieces[piece_index]:
                    with self.lock:
                        self.downloaded[piece_index] = True
                        self.file_handle.seek(piece_index * self.piece_length)
                        self.file_handle.write(data)
                        self.downloaded_pieces += 1
                        percent = (self.downloaded_pieces / self.total_pieces) * 100
                        print(f"\rDownload progress: {percent:.2f}%", end='')
                else:
                    print(f"\nMã băm của piece {piece_index} không khớp. Đang đưa lại vào queue.")
                    self.retry_piece(piece_index)
            else:
                print(f"\nKhông nhận được dữ liệu cho piece {piece_index} từ {ip}:{port}")
                self.retry_piece(piece_index)

            s.close()
        except Exception as e:
            print(f"\nError downloading piece {piece_index} từ {ip}:{port} - {e}")
            self.retry_piece(piece_index)
            s.close()

    def recvall(self, sock, n):
        """Hàm hỗ trợ nhận tất cả các byte cần thiết"""
        data = b''
        while len(data) < n:
            try:
                packet = sock.recv(n - len(data))
                if not packet:
                    return None
                data += packet
            except socket.timeout:
                return None
            except Exception as e:
                print(f"Error receiving data: {e}")
                return None
        return data

    def retry_piece(self, piece_index):
        """Retry tải lại một piece nếu chưa đạt số lần tối đa"""
        with self.lock:
            if self.retry_counts[piece_index] < self.max_retries:
                self.retry_counts[piece_index] += 1
                print(f"\nRetrying piece {piece_index}. Lần thứ {self.retry_counts[piece_index]}")
                self.piece_queue.put(piece_index)
            else:
                print(f"\nĐã đạt số lần retry tối đa cho piece {piece_index}. Bỏ qua piece này.")

    def verify_file_hash(self):
        """Kiểm tra mã băm SHA1 tổng thể của tệp tải xuống"""
        print("\nĐang kiểm tra mã băm SHA1 tổng thể của tệp tải xuống...")
        sha1 = hashlib.sha1()
        try:
            with open(self.file, 'rb') as f:
                while True:
                    data = f.read(self.piece_length)
                    if not data:
                        break
                    sha1.update(data)
            computed_hash = sha1.hexdigest()
            if computed_hash == self.overall_hash:
                print(f"Mã băm SHA1 tổng thể khớp: {computed_hash}. Tệp tải xuống hoàn toàn chính xác.")
            else:
                print(f"Mã băm SHA1 tổng thể không khớp! Đã có lỗi trong quá trình tải xuống.")
                print(f"Mã băm gốc: {self.overall_hash}")
                print(f"Mã băm tính toán: {computed_hash}")
        except Exception as e:
            print(f"Lỗi khi kiểm tra mã băm của tệp: {e}")

def main():
    print("===== Torrent Client =====")
    print("1. Tạo và Upload Tệp Torrent")
    print("2. Download Tệp Torrent")
    choice = input("Chọn một tùy chọn (1 hoặc 2): ")

    tracker_client = TrackerClient(TRACKER_URL)

    if choice == '1':
        file_path = input("Nhập đường dẫn đến tệp bạn muốn chia nhỏ: ")
        if not os.path.exists(file_path):
            print("Tệp không tồn tại. Vui lòng kiểm tra lại đường dẫn.")
            return

        # Tạo metainfo và tính toán info_hash
        client_temp = TorrentClient('', 0, tracker_client)
        torrent_path = client_temp.create_metainfo(file_path)
        info_hash = client_temp.info_hash

        # Kiểm tra xem info_hash đã tồn tại trên Tracker chưa
        exists = tracker_client.check_hash(info_hash)
        if exists:
            print("\n`info_hash` đã tồn tại trên Tracker. Không cần tạo và upload lại tệp torrent.")
            # Khởi động Seeder
            peer_id = input("Nhập peer_id cho Seeder: ")
            try:
                port = int(input("Nhập port để Seeder lắng nghe: "))
            except ValueError:
                print("Port không hợp lệ. Vui lòng nhập một số nguyên.")
                return
            client = TorrentClient(peer_id, port, tracker_client)
            client.load_metainfo(torrent_path)
            client.start_seeder()
        else:
            # Upload tệp torrent lên Tracker
            upload_response = tracker_client.upload_torrent(torrent_path, info_hash)
            if upload_response.get('status') == 'success':
                print("\nTệp torrent đã được upload thành công lên Tracker.")
                # Khởi động Seeder
                peer_id = input("Nhập peer_id cho Seeder: ")
                try:
                    port = int(input("Nhập port để Seeder lắng nghe: "))
                except ValueError:
                    print("Port không hợp lệ. Vui lòng nhập một số nguyên.")
                    return
                client = TorrentClient(peer_id, port, tracker_client)
                client.load_metainfo(torrent_path)
                client.start_seeder()
            elif upload_response.get('status') == 'exists':
                print("\nTệp torrent đã tồn tại trên Tracker. Không cần upload lại.")
                # Khởi động Seeder
                peer_id = input("Nhập peer_id cho Seeder: ")
                try:
                    port = int(input("Nhập port để Seeder lắng nghe: "))
                except ValueError:
                    print("Port không hợp lệ. Vui lòng nhập một số nguyên.")
                    return
                client = TorrentClient(peer_id, port, tracker_client)
                client.load_metainfo(torrent_path)
                client.start_seeder()
            else:
                print(f"Upload thất bại: {upload_response.get('message')}")
    elif choice == '2':
        # Chọn và tải xuống tệp torrent từ Tracker
        client_temp = TorrentClient('', 0, tracker_client)
        torrent_path = client_temp.select_torrent()
        if not torrent_path:
            return
        # Nhập peer_id và port cho Leecher
        peer_id = input("Nhập peer_id cho Leecher: ")
        try:
            port = int(input("Nhập port để Leecher lắng nghe: "))
        except ValueError:
            print("Port không hợp lệ. Vui lòng nhập một số nguyên.")
            return
        # Khởi động Leecher
        client = TorrentClient(peer_id, port, tracker_client)
        client.load_metainfo(torrent_path)
        client.start_leecher()
    else:
        print("Lựa chọn không hợp lệ. Vui lòng chạy lại chương trình và chọn 1 hoặc 2.")

if __name__ == '__main__':
    main()
