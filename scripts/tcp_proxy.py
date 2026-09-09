#!/usr/bin/env python3
import socket
import threading
import select
import sys

def handle(client, target_host, target_port):
    try:
        server = socket.create_connection((target_host, target_port))
    except Exception as e:
        print(f"[proxy] failed to connect to {target_host}:{target_port} - {e}")
        client.close()
        return

    while True:
        r, _, _ = select.select([client, server], [], [])
        if client in r:
            data = client.recv(4096)
            if not data:
                break
            server.sendall(data)
        if server in r:
            data = server.recv(4096)
            if not data:
                break
            client.sendall(data)
            
    client.close()
    server.close()

def main():
    if len(sys.argv) != 5:
        print("Usage: proxy.py <bind_ip> <bind_port> <target_ip> <target_port>")
        sys.exit(1)
        
    bind_ip, bind_port, target_ip, target_port = sys.argv[1:5]
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind_ip, int(bind_port)))
    s.listen(5)
    
    print(f"[proxy] listening on {bind_ip}:{bind_port}, forwarding to {target_ip}:{target_port}")
    
    while True:
        try:
            c, addr = s.accept()
            threading.Thread(target=handle, args=(c, target_ip, int(target_port)), daemon=True).start()
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    main()
