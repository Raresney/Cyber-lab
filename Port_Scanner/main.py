import socket
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"

services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

banner_triggers = {
    80: b"GET / HTTP/1.0\r\n\r\n",
    8080: b"GET / HTTP/1.0\r\n\r\n",
    443: b"GET / HTTP/1.0\r\n\r\n",
}

print(f"Scanning {target}...\n")

for port, service in services.items():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    result = sock.connect_ex((target, port))

    if result == 0:
        print(f"[OPEN]  Port {port:5} — {service}")

        trigger = banner_triggers.get(port)
        if trigger:
            try:
                sock.sendall(trigger)
            except socket.error:
                pass

        try:
            banner = sock.recv(1024).decode(errors="replace").strip()
            if banner:
                first_line = banner.splitlines()[0]
                print(f"         Banner: {first_line}")
        except socket.error:
            pass
    else:
        print(f"[closed] Port {port:5} — {service}")

    sock.close()

print("\nScan complete.")
