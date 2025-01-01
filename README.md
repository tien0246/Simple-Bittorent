# Simple-BitTorrent

Simple-BitTorrent is a lightweight BitTorrent implementation written in Python, designed for educational purposes. It includes functionalities for creating torrents, peer-to-peer communication, and managing a tracker to facilitate file sharing. The project demonstrates the core principles of the BitTorrent protocol with a focus on simplicity and modularity.

## Features

### Node (Peer)
- **Torrent Creation:** Generate `.torrent` files for single files or entire directories, with detailed piece hashing and metadata generation.
- **Seeding:** Share files with other peers in the network efficiently and securely.
- **Leeching:** Download files from peers while verifying their integrity in real-time.
- **File Integrity:** Ensure downloaded files are complete and uncorrupted using SHA-1 hash checks for each piece.
- **Bitfield Management:** Manage availability and requests for pieces using an efficient bitfield representation.
- **Encryption:** Protect piece transmission during downloads using AES-GCM for secure communication.

### Tracker
- **User Authentication:** Provides endpoints for user sign-up, login, and session management to ensure secure operations.
- **Torrent Management:**
  - Upload and store `.torrent` files.
  - Announce events such as `started`, `stopped`, and `completed` to track download progress.
  - Retrieve torrent statistics, including the number of seeders, leechers, and completed downloads.
- **Peer Management:** Maintain and update the list of active peers for each torrent dynamically.

## Requirements

- Python 3.8 or higher
- Libraries:
  - `flask`: For implementing the tracker as a web server.
  - `bencodepy`: For encoding and decoding `.torrent` files.
  - `cryptography`: For AES-GCM encryption.
  - `questionary`: For interactive CLI menus.
  - `alive-progress`: For dynamic progress bars during operations.
  - `tabulate`: For formatting tables in CLI outputs.
  - `requests`: For HTTP communication with the tracker.
  - `psutil`: For retrieving system and network information.

Install dependencies using:
```bash
pip install -r requirements.txt
```

## Usage

### Tracker Setup
1. Start the tracker server by running:
   ```bash
   python tracker.py
   ```
2. The tracker will host endpoints at `http://<server_ip>:8000` for managing torrents and peers.

### Node (Peer) Setup
1. Start the node by running:
   ```bash
   python node.py
   ```
2. Follow the interactive CLI prompts to:
   - Register or log in to the tracker.
   - Become a seeder to share files.
   - Become a leecher to download files.

### Creating a Torrent
- Use the "Become Seeder" option to select a file or directory and generate a corresponding `.torrent` file with all required metadata.

### Seeding
- After creating a `.torrent` file, select "Become Seeder" to start sharing the file with other peers in the network.

### Leeching
- Choose "Become Leecher" to list available torrents from the tracker and download a selected file.

## Project Structure

```plaintext
.
├── node.py          # Peer implementation: Handles torrent creation, seeding, and leeching
├── tracker.py       # Tracker implementation: Manages torrents and peer lists
├── requirements.txt # Project dependencies
├── torrents/        # Directory for storing `.torrent` files
├── downloads/       # Directory for storing downloaded files
```

## Notes

- **File Integrity:** The system ensures file integrity by validating every downloaded piece against its SHA-1 hash.
- **Security:** Peer communication is encrypted using AES-GCM, providing a secure channel for data transfer.
- **Extensibility:** The modular design allows for easy integration of advanced features like Distributed Hash Tables (DHT) and magnet link support.
- **Logging:** Debug logs can be toggled on or off to assist with development and troubleshooting.

## License
This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer
This project is for educational purposes only and should not be used for illegal file sharing.
