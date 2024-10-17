# tracker.py
from flask import Flask, request, jsonify, send_from_directory
import os
import threading
import json

app = Flask(__name__)

TORRENTS_DIR = 'torrents'
HASHES_FILE = 'hashes.json'
PEERS = {}
LOCK = threading.Lock()

# Đảm bảo thư mục torrents tồn tại
if not os.path.exists(TORRENTS_DIR):
    os.makedirs(TORRENTS_DIR)

# Tải hashes từ file JSON
if os.path.exists(HASHES_FILE):
    with open(HASHES_FILE, 'r') as f:
        HASHES = json.load(f)
else:
    HASHES = {}

@app.route('/announce', methods=['GET'])
def announce():
    info_hash = request.args.get('info_hash')
    peer_id = request.args.get('peer_id')
    port = request.args.get('port')
    event = request.args.get('event', 'started')
    ip = request.remote_addr

    if not info_hash or not peer_id or not port:
        return jsonify({'status': 'fail', 'message': 'Missing parameters'}), 400

    with LOCK:
        if info_hash not in PEERS:
            PEERS[info_hash] = []
        
        # Loại bỏ peer hiện tại nếu đã tồn tại
        PEERS[info_hash] = [peer for peer in PEERS[info_hash] if peer['peer_id'] != peer_id]
        
        if event != 'stopped':
            # Thêm peer vào danh sách
            PEERS[info_hash].append({
                'ip': ip,
                'port': int(port),
                'peer_id': peer_id
            })
        else:
            # Nếu event là 'stopped', loại bỏ peer khỏi danh sách
            PEERS[info_hash] = [peer for peer in PEERS[info_hash] if peer['peer_id'] != peer_id]
        
        # Chuẩn bị danh sách peers để gửi lại, loại bỏ peer hiện tại
        response_peers = [peer for peer in PEERS[info_hash] if peer['peer_id'] != peer_id]
    
    return jsonify({'peers': response_peers}), 200

@app.route('/upload_torrent', methods=['POST'])
def upload_torrent():
    if 'torrent' not in request.files or 'info_hash' not in request.form:
        return jsonify({'status': 'fail', 'message': 'Missing torrent file or info_hash'}), 400

    torrent = request.files['torrent']
    info_hash = request.form['info_hash']

    if torrent.filename == '':
        return jsonify({'status': 'fail', 'message': 'No selected file'}), 400

    with LOCK:
        if info_hash in HASHES:
            return jsonify({'status': 'exists', 'message': 'Torrent already exists'}), 200

        # Lưu tệp torrent
        torrent_path = os.path.join(TORRENTS_DIR, torrent.filename)
        torrent.save(torrent_path)

        # Cập nhật HASHES và lưu vào file JSON
        HASHES[info_hash] = torrent.filename
        with open(HASHES_FILE, 'w') as f:
            json.dump(HASHES, f, indent=4)

    return jsonify({'status': 'success', 'message': 'Torrent uploaded successfully'}), 200

@app.route('/list_torrents', methods=['GET'])
def list_torrents():
    with LOCK:
        torrents = list(HASHES.values())
    return jsonify({'torrents': torrents}), 200

@app.route('/torrents/<filename>', methods=['GET'])
def get_torrent(filename):
    """Endpoint để tải xuống tệp torrent"""
    return send_from_directory(TORRENTS_DIR, filename, as_attachment=True)

@app.route('/check_hash', methods=['GET'])
def check_hash():
    info_hash = request.args.get('info_hash')
    if not info_hash:
        return jsonify({'status': 'fail', 'message': 'Missing info_hash parameter'}), 400

    with LOCK:
        exists = info_hash in HASHES

    return jsonify({'exists': exists}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, threaded=True)
