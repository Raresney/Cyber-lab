#!/bin/bash
echo "[*] Installing dependencies..."
sudo apt update
sudo apt install vsftpd hydra -y

echo "[*] Starting FTP service..."
sudo systemctl start vsftpd

echo "[*] Creating test user..."
sudo useradd -m -s /bin/bash testuser 2>/dev/null
echo "testuser:password123" | sudo chpasswd

echo "[*] Setup complete."
echo "[*] Run: hydra -I -l testuser -P wordlists/test_wordlist.txt ftp://127.0.0.1 -t 4 -V"