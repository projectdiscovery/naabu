import socket, sys, threading, time


def serve(p):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", p))
    s.listen(128)
    while True:
        try:
            c, _ = s.accept()
            c.close()
        except Exception:
            pass


for a in sys.argv[1:]:
    threading.Thread(target=serve, args=(int(a),), daemon=True).start()

while True:
    time.sleep(3600)
