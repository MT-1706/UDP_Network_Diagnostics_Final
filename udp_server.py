import socket, sys

try:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9999      # port from the command line, else 9999
except ValueError:
    sys.exit("usage: udp_server.py [port]")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind(("0.0.0.0", port))                                   # listen on every interface
except OSError as e:                                            # e.g. port already in use
    sys.exit(f"cannot bind UDP port {port}: {e}")
print(f"UDP echo server on port {port}", flush=True)
try:
    while True:
        try:
            data, addr = s.recvfrom(2048)                       # wait for a packet
            s.sendto(data, addr)                                # send the same bytes back
        except OSError:                                         # e.g. ICMP error from an earlier send: keep serving
            continue
except KeyboardInterrupt:
    pass
