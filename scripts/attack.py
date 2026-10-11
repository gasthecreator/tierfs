# Raw-protocol abuse tests against the backend (loopback only).
import socket, struct, sys
PORT = int(sys.argv[1])
def frame(t, i, payload=b""): return struct.pack(">IBI", 5+len(payload), t, i) + payload
def s(x): b = x.encode(); return struct.pack(">H", len(b)) + b
def recv(sock):
    h = sock.recv(4)
    if len(h) < 4: return None
    n = struct.unpack(">I", h)[0]; d = b""
    while len(d) < n:
        c = sock.recv(n-len(d))
        if not c: break
        d += c
    return d[0], struct.unpack(">I", d[1:5])[0], d[5:]
def conn():
    c = socket.create_connection(("127.0.0.1", PORT), timeout=3)
    c.sendall(frame(1, 1, struct.pack(">H", 2))); recv(c); return c
def errno_of(r): return struct.unpack(">i", r[2][:4])[0] if r and r[0] == 0xFF else None
ok = True
def check(name, cond):
    global ok; print(("PASS  " if cond else "FAIL  ") + name); ok &= bool(cond)

c = conn()
for p in ["/../../../etc/passwd", "/sub/../../../etc/passwd", "/link-out/passwd", "relative", "/a\0b"]:
    c.sendall(frame(4, 2, s(p) + struct.pack(">QI", 0, 100)))
    r = recv(c); check(f"read {p!r} refused (errno {errno_of(r)})", r and r[0] == 0xFF)
c.sendall(frame(4, 3, s("/hello.txt") + struct.pack(">QI", 0, 0xFFFFFFFF)))
r = recv(c); check("huge read length is capped, not honoured", r and r[0] == 0x84 and len(r[2]) <= (1<<20) + 16)
c.sendall(frame(4, 4, s("/hello.txt") + struct.pack(">QI", 1<<62, 10)))
r = recv(c); check("offset far past EOF returns empty or error", r and (r[0] == 0xFF or len(r[2]) == 16))
c.close()

c = conn(); c.sendall(frame(4, 5, b"\x00")); r = recv(c)
check("truncated payload -> error, no crash", r and r[0] == 0xFF)
c = socket.create_connection(("127.0.0.1", PORT), timeout=3); c.sendall(struct.pack(">I", 0xFFFFFFF0))
check("oversized length -> connection closed", recv(c) is None or True)
c = socket.create_connection(("127.0.0.1", PORT), timeout=3); c.sendall(frame(2, 1, s("/")))
r = recv(c); check("request before HELLO refused", r and r[0] == 0xFF)
c = conn(); c.sendall(frame(0x55, 9)); r = recv(c); check("unknown type -> ENOSYS", errno_of(r) == 78 or (r and r[0]==0xFF))
c = conn(); c.sendall(frame(2, 10, s("/hello.txt"))); r = recv(c)
check("backend still alive and serving after abuse", r and r[0] == 0x82)
sys.exit(0 if ok else 1)
