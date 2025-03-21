from flask import *
import json
import bencodepy # type: ignore
import threading
import hashlib
import time
import os
from functools import wraps

app = Flask(__name__)
app.secret_key = 'secret_key'
lock = threading.Lock()
current_dir = os.path.dirname(os.path.abspath(__file__))
torrents_dir = os.path.join(current_dir, 'torrents')
hash_file = os.path.join(current_dir, 'hashes.json')
users_file = os.path.join(current_dir, 'users.json')
torrents_file = os.path.join(current_dir, 'torrents.json')
peers_file = os.path.join(current_dir, 'peers.json')

if not os.path.exists(torrents_dir):
    os.makedirs(torrents_dir)
    
def load_json(filename):
    with lock:
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except:
            return {}

def save_json(filename, data):
    with lock:
        with open(filename, 'w') as f:
            json.dump(data, f)

def make_bencoded_response(message, status_code):
    response_data = bencodepy.encode(message)
    response = make_response(response_data)
    response.headers['Content-Type'] = 'text/plain'
    response.status_code = status_code
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return make_bencoded_response({'failure reason': 'Authentication required.'}, 401)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    users = load_json(users_file)
    if data['username'] in users:
        return make_bencoded_response({'failure reason': 'User exists'}, 400)
    users[data['username']] = hashlib.sha256(data['password'].encode()).hexdigest()
    save_json(users_file, users)
    return make_bencoded_response({'status': 'success'}, 200)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    users = load_json(users_file)
    if users.get(data['username']) == hashlib.sha256(data['password'].encode()).hexdigest():
        session['username'] = data['username']
        return make_bencoded_response({'status': 'success'}, 200)
    return make_bencoded_response({'failure reason': 'Invalid credentials'}, 400)

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    session.pop('username', None)
    return make_bencoded_response({'status': 'success'}, 200)

@app.route('/announce', methods=['GET'])
@login_required
def announce():
    try:
        required_params = ['info_hash', 'ip', 'peer_id', 'event']
        missing_params = [param for param in required_params if not request.args.get(param)]
        if missing_params:
            return make_bencoded_response({'failure reason': f'Missing required parameters: {", ".join(missing_params)}'}, 400)
        info_hash = request.args.get('info_hash')
        peer_id = request.args.get('peer_id')
        ip = request.args.get('ip')
        port = request.args.get('port')
        uploaded = request.args.get('uploaded')
        downloaded = request.args.get('downloaded')
        left = request.args.get('left')
        event = request.args.get('event')

        peers = load_json(peers_file)
        torrents = load_json(torrents_file)
        if info_hash not in peers:
            peers[info_hash] = {}
            if info_hash not in torrents:
                return make_bencoded_response({'failure reason': 'Not found'}, 404)
        if event == 'started':
            required_params = ['port', 'uploaded', 'downloaded', 'left']
            missing_params = [param for param in required_params if not request.args.get(param)]
            
            if missing_params:
                return make_bencoded_response({'failure reason': f'Missing required parameters: {", ".join(missing_params)}'}, 400)
            peer_info = {
                'ip': ip,
                'port': int(port),
                'uploaded': int(uploaded),
                'downloaded': int(downloaded),
                'left': int(left)
            }
            if peer_id not in peers[info_hash]:
                peers[info_hash][peer_id] = peer_info
                torrents[info_hash]['seeder' if int(left) == 0 else 'leecher'] += 1
            else:
                peers[info_hash][peer_id].update(peer_info)
        elif event == 'stopped':
            if peer_id in peers[info_hash]:
                torrents[info_hash]['seeder' if peers[info_hash][peer_id]['left'] == 0 else 'leecher'] -= 1
                del peers[info_hash][peer_id]
                if not peers[info_hash]:
                    del peers[info_hash]
            save_json(peers_file, peers)
            save_json(torrents_file, torrents)
            return make_bencoded_response({'status': 'success'}, 200)      
        elif event == 'completed':
            if peer_id in peers[info_hash]:
                peers[info_hash][peer_id]['left'] = 0
                torrents[info_hash]['seeder'] += 1
                torrents[info_hash]['leecher'] -= 1
                torrents[info_hash]['completed'] += 1
            save_json(peers_file, peers)
            save_json(torrents_file, torrents)
            return make_bencoded_response({'status': 'success'}, 200)  
        else:
            return make_bencoded_response({'failure reason': 'Invalid event'}, 400)
        save_json(peers_file, peers)
        save_json(torrents_file, torrents)
        response_dict = {
            'peers': peers[info_hash]
        }
        return make_bencoded_response(response_dict, 200)
    except Exception as e:
        return make_bencoded_response({'failure reason': f'Unexpected error: {str(e)}'}, 500)
    
@app.route('/upload_torrent', methods=['POST'])
@login_required
def upload_torrent():
    required_params = ['info_hash', 'name']
    missing_params = [param for param in required_params if not request.form.get(param)]
    if missing_params:
        return make_bencoded_response({'failure reason': f'Missing required parameters: {", ".join(missing_params)}'}, 400)
    if not request.form.get('file_size') and not request.form.get('path'):
        return make_bencoded_response({'failure reason': 'Missing file_size or path'}, 400)
    torrent_file = request.files.get('torrent')
    if not torrent_file:
        return make_bencoded_response({'failure reason': 'Missing torrent file'}, 400)
    info_hash = request.form['info_hash']
    name = request.form['name']
    torrents = load_json(torrents_file)
    if info_hash in torrents:
        return make_bencoded_response({'failure reason': 'Torrent already exists'}, 400)
    torrents[info_hash] = {
        'name': name,
        'date_uploaded': int(time.time()),
        'created_by': session['username'],
        'seeder': 0,
        'leecher': 0,
        'completed': 0
    }
    file_size = request.form.get('file_size')
    if file_size:
        try:
            file_size = int(file_size)
            torrents[info_hash]['file_size'] = file_size
        except ValueError:
            return make_bencoded_response({'failure reason': 'Invalid file size'}, 400)
    else:
        torrents[info_hash]['path'] = json.loads(request.form.get('path'))
    save_json(torrents_file, torrents)
    torrent_path = f"{torrents_dir}/{info_hash + '.torrent'}"
    torrent_file.save(torrent_path)
    return make_bencoded_response({'status': 'success'}, 200)

@app.route('/scrape', methods=['GET'])
@login_required
def scrape():
    required_params = ['info_hash']
    missing_params = [param for param in required_params if not request.form.get(param)]
    if missing_params:
        return make_bencoded_response({'failure reason': f'Missing required parameters: {", ".join(missing_params)}'}, 400)
    info_hash = request.args.get('info_hash')
    torrents = load_json(torrents_file)
    if info_hash not in torrents:
        return make_bencoded_response({'failure reason': 'Not found'}, 404)
    response_dict = {
        'seeder': torrents[info_hash]['seeder'],
        'leecher': torrents[info_hash]['leecher'],
        'completed': torrents[info_hash]['completed']
    }
    return make_bencoded_response(response_dict, 200)

@app.route('/list_torrents', methods=['GET'])
@login_required
def list_torrents():
    torrents = load_json(torrents_file)
    return make_bencoded_response(torrents, 200)

@app.route('/download_torrent/<info_hash>', methods=['GET'])
def get_torrent(info_hash):
    torrents = load_json(torrents_file)
    if info_hash not in torrents:
        return make_bencoded_response({'failure reason': 'Not found'}, 404)
    return send_from_directory(torrents_dir, info_hash + '.torrent', as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, threaded=True)