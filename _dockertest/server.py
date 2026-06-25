import socket, sys, threading, time


def serve(family, addr, p):
    s = socket.socket(family, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if family == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, p))
    s.listen(128)
    while True:
        try:
            c, _ = s.accept()
            c.close()
        except Exception:
            pass


for a in sys.argv[1:]:
    p = int(a)
    threading.Thread(target=serve, args=(socket.AF_INET, "0.0.0.0", p), daemon=True).start()
    try:
        threading.Thread(target=serve, args=(socket.AF_INET6, "::", p), daemon=True).start()
    except Exception:
        pass

while True:
    time.sleep(3600)
