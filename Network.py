import random, string, hashlib, pickle, typing, util, socket, threading, psutil, time, traceback, ssl, queue, collections, base64
def GENERAL_DELAY():
    return psutil.cpu_percent(interval=None)/4000
HASH_SIZE=-1
def hash_hex(data: bytes) -> bytes:
    """Return SHA-512 hex digest as bytes."""
    if isinstance(data, str):
        data = util.str_to_bytes(data)
    return util.str_to_bytes(hashlib.sha1(data).hexdigest())[:HASH_SIZE]
ID_LEN = 64
HASH_SIZE = len(hash_hex(b''))
CHUNK_SIZE = 65536
DEFAULT_MAX_RETRIES = 10
DEFAULT_IP = None
for x in socket.getaddrinfo(socket.gethostname(), None):
    _ip = x[4][0]
    if x[0] != socket.AF_INET:continue
    if _ip.startswith("127."):continue
    DEFAULT_IP = _ip;break
LOCKS=dict()
def gen_ID() -> str:
    return ''.join(random.choices(string.ascii_letters + string.digits, k=ID_LEN))
def config(*, retries=None, chunk_size=None, id_len=None, hash_size=None):
    global DEFAULT_MAX_RETRIES, CHUNK_SIZE, ID_LEN, HASH_SIZE
    if retries!=None:DEFAULT_MAX_RETRIES=bool(retries)
    if chunk_size!=None:CHUNK_SIZE=int(chunk_size)
    if id_len!=None:ID_LEN=int(id_len)
    if hash_size!=None:HASH_SIZE=int(hash_size)
def serialize(data: typing.Any, PICKLE=True) -> bytes:
    if PICKLE and not isinstance(data, bytes):data = pickle.dumps(data, protocol=pickle.HIGHEST_PROTOCOL)
    return base64.b64encode(util.str_to_bytes(data))
def deserialize(data: bytes, PICKLE=True) -> typing.Any:
    data = base64.b64decode(data)
    if PICKLE:
        try:return pickle.loads(data)
        except Exception:return data
    return data
def _send(sock, data):
    if sock not in LOCKS:LOCKS[sock]=threading.Lock()
    with LOCKS[sock]:
        sock.sendall(data)
class Server:
    def __init__(self, *, host_ip=None, host_port=0, chunk_size=None, max_retries=None, prv_key, cert_key):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls_context.load_cert_chain(certfile=cert_key,keyfile=prv_key)
        self.tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.host_ip = host_ip or DEFAULT_IP
        self.host_port = host_port
        if not chunk_size:chunk_size=CHUNK_SIZE
        self.chunk_size = chunk_size
        if not max_retries:max_retries=DEFAULT_MAX_RETRIES
        self.max_retries = max_retries
        self.clients = {}
        self.hasher_queue = queue.Queue()
        self.router_queue = []
        self.router_cursor = 0
        self.recv_queue = collections.defaultdict(collections.deque)
        self.cont_queue = {}
        self.cont_queue_time = {}
        self.threads = {}
        self.SEND_LOCK = {}
        self.status = {}
        self.on_new_threads=dict()
    def start(self):
        self.server.bind((self.host_ip, self.host_port))
        self.server.listen(50)
        self.server.setblocking(False)
        threading.Thread(target=self.router).start()
        threading.Thread(target=self.recv_all).start()
        threading.Thread(target=self.listen).start()
        threading.Thread(target=self.hash_worker).start()
    def listen(self):
        while True:
            try:_client_sock, addr = self.server.accept()
            except:
                time.sleep(GENERAL_DELAY())
                continue
            try:client_sock = self.tls_context.wrap_socket(_client_sock,server_side=True)
            except Exception:_client_sock.close();continue
            client_sock.setblocking(False)
            CID = gen_ID()
            self.clients[CID] = client_sock
            self.SEND_LOCK[CID] = threading.RLock()
    def recv_all(self):
        buffers = {}
        while True:
            try:
                items = list(self.clients.items())
                any_activity = False
                for CID, sock in items:
                    try:data = sock.recv(65536)
                    except Exception:continue
                    if not data:continue
                    any_activity = True
                    buf = buffers.get(CID, b"") + data
                    if len(buf) > self.chunk_size * 8:buf = buf[-self.chunk_size * 8:]
                    while True:
                        start = buf.find(b'~')
                        if start == -1:
                            buf = b""
                            break
                        end = buf.find(b'~', start + 1)
                        if end == -1:
                            buf = buf[start:]
                            break
                        frame = buf[start + 1:end]
                        buf = buf[end + 1:]
                        if frame == b'1':
                            self.status[CID] = 1
                            continue
                        if frame == b'0':
                            self.status[CID] = 0
                            continue
                        if len(frame) < (2 * ID_LEN + HASH_SIZE + 1):
                            continue
                        MID = frame[0:ID_LEN]
                        TID = frame[ID_LEN:2 * ID_LEN]
                        payload = frame[2 * ID_LEN:-(HASH_SIZE + 1)]
                        msg_hash = frame[-(HASH_SIZE + 1):-1]
                        cont_flag = frame[-1] == ord('1')
                        self.hasher_queue.put(
                            (CID, MID, TID, payload, msg_hash, cont_flag)
                        )
                    buffers[CID] = buf
            except Exception as e:traceback.print_exception(e)
            if not any_activity:
                time.sleep(0)
    def hash_worker(self):
        while True:
            CID, MID, TID, payload, msg_hash, cont_flag = self.hasher_queue.get()
            try:
                if hash_hex(payload) == msg_hash:
                    try:_send(self.clients[CID], b'~1~')
                    except:pass
                    self.router_queue.append((CID, MID, TID, payload, cont_flag))
                else:
                    try:_send(self.clients[CID], b'~0~')
                    except:pass
            except:pass
    def send(self, data, CID, TID=None, PICKLE=True, timeout=5.0):
        if isinstance(data, bytes):PICKLE = False
        body_bytes = serialize(data, PICKLE=PICKLE)
        cid_key = CID
        sock = self.clients.get(cid_key)
        if sock==None:raise RuntimeError("Unknown CID or disconnected client")
        MID_str = gen_ID()
        if TID==None:TID_str = gen_ID()
        else:TID_str = util.bytes_to_str(TID)
        MID_b = util.str_to_bytes(MID_str)
        TID_b = util.str_to_bytes(TID_str)
        if len(MID_b) != ID_LEN or len(TID_b) != ID_LEN:
            raise ValueError("MID/TID must be ID_LEN bytes when encoded")
        chunks = []
        offset = 0
        available_body = self.chunk_size - (ID_LEN + ID_LEN + HASH_SIZE + 3)
        total_len = len(body_bytes)
        while offset < total_len:
            end = min(offset + available_body, total_len)
            chunks.append(body_bytes[offset:end])
            offset = end
        prepared_msgs = []
        for i, segment in enumerate(chunks):
            segment_b = util.str_to_bytes(segment)
            seg_hash = util.str_to_bytes(hash_hex(segment_b))
            cont_flag = b'1' if i < len(chunks) - 1 else b'0'
            msg = b'~' + MID_b + TID_b + segment_b + seg_hash + cont_flag + b'~'
            prepared_msgs.append(msg)
        lock = self.SEND_LOCK.get(cid_key)
        for msg in prepared_msgs:
            retries = self.max_retries
            while retries > 0:
                self.status[cid_key] = -1
                with lock:_send(sock, msg)
                deadline = time.time() + float(timeout)
                while True:
                    ack = self.status[cid_key]
                    if ack in (0, 1):break
                    if time.time() >= deadline:break
                    time.sleep(0)
                if ack == 1:break
                retries -= 1
                if retries == 0:return False
        return True
    def on_new_thread(CID, TID):pass
    @property
    def NEW_DATA(self, CID=None, TID=None):
        if not (CID or TID):return len(self.recv_queue)>0
        queue=self.recv_queue.copy()
        for cid, tid, _ in queue:
            if CID and cid!=CID:continue
            if TID and tid!=TID:continue
            return True
        return False
    def router(self):
        while True:
            time.sleep(GENERAL_DELAY())
            if self.router_cursor >= len(self.router_queue):
                continue
            if self.router_cursor > 500:
                self.router_queue = self.router_queue[self.router_cursor:]
                self.router_cursor = 0
            now = time.time()
            for key, t0 in list(self.cont_queue_time.items()):
                if now - t0 > 30:
                    self.cont_queue.pop(key, None)
                    self.cont_queue_time.pop(key, None)
            if self.router_cursor < len(self.router_queue):
                item = self.router_queue[self.router_cursor]
                self.router_cursor += 1
            else:continue
            CID, MID, TID, payload, cont_flag = item
            key = (MID, TID)
            if cont_flag:
                if key not in self.cont_queue:self.cont_queue[key] = payload
                else:self.cont_queue[key] += payload
                self.cont_queue_time[key] = now
            else:
                if key in self.cont_queue:
                    full_payload = self.cont_queue.pop(key) + payload
                    self.cont_queue_time.pop(key, None)
                else:full_payload = payload
                self.recv_queue[CID].append((TID, full_payload))
                if CID not in self.threads:
                    self.threads[CID]=[]
                if TID not in self.threads[CID]:
                    self.threads[CID].append(TID)
                    t = threading.Thread(target=self.on_new_thread,kwargs={'CID': CID, 'TID': TID})
                    t.start()
    def recv(self, CID, TID=None, PICKLE=True, blocking=True, timeout=-1):
        if blocking:
            stime = time.time()
            while timeout == -1 or time.time() - stime < timeout:
                data = self.recv(CID=CID, TID=TID, PICKLE=PICKLE, blocking=False)
                if data!=None:return data
                time.sleep(GENERAL_DELAY())
            return None
        q = self.recv_queue.get(CID)
        if not q:return None
        for i in range(len(q)):
            tid, payload = q[i]
            if TID==None or tid == TID:
                q.remove(q[i])
                return deserialize(payload, PICKLE=PICKLE)
        return None
class Client:
    def __init__(self, *, client_ip=None, client_port, server_ip, server_port, chunk_size=None, max_retries=None, ca_cert=''):
        self.server_ip = server_ip
        self.server_port = server_port
        if not client_ip:client_ip=DEFAULT_IP
        self.client_ip = client_ip
        self.client_port = client_port
        if not chunk_size:chunk_size=CHUNK_SIZE
        self.chunk_size = chunk_size
        if not max_retries:max_retries=DEFAULT_MAX_RETRIES
        self.max_retries = max_retries
        self.threads = []
        self.sock = None
        self.cont_queue = {}
        self.cont_queue_time = {}
        self.SEND_LOCK = threading.RLock()
        self.status = {}
        self.router_queue = []
        self.router_cursor = 0
        self.recv_queue = []
        if ca_cert:
            self.tls_context.load_verify_locations(cafile="CA_cert.pem")
        else:
            self.tls_context = ssl.create_default_context()
            self.tls_context.check_hostname = False
            self.tls_context.verify_mode = ssl.CERT_NONE
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._sock.bind((self.client_ip, self.client_port))
        try:
            self._sock.connect((self.server_ip, self.server_port))
        except:exit('Server not ready')
        self.sock = self.tls_context.wrap_socket(self._sock,server_hostname=self.server_ip)
        self.sock.setblocking(False)
        threading.Thread(target=self.router).start()
        threading.Thread(target=self.recv_all).start()
    def recv_all(self):
        buffer = bytearray()
        while True:
            time.sleep(GENERAL_DELAY())
            try:
                data = self.sock.recv(65536)
            except (BlockingIOError, ssl.SSLWantReadError):
                continue
            except Exception as e:
                traceback.print_exception(e)
                continue
            if not data:
                continue
            buffer.extend(data)
            if len(buffer) > 10_000_000:
                buffer.clear()
            while True:
                try:
                    start = buffer.index(ord('~'))
                except ValueError:
                    buffer.clear()
                    break
                try:
                    end = buffer.index(ord('~'), start + 1)
                except ValueError:
                    buffer[:] = buffer[start:]
                    break
                frame = buffer[start + 1:end]
                del buffer[:end + 1]
                if frame == b'1':
                    self.status = 1
                    continue
                if frame == b'0':
                    self.status = 0
                    continue
                if len(frame) < (2 * ID_LEN + HASH_SIZE + 1):
                    continue
                MID = bytes(frame[0:ID_LEN])
                TID = bytes(frame[ID_LEN:2 * ID_LEN])
                payload = bytes(frame[2 * ID_LEN:-(HASH_SIZE + 1)])
                msg_hash = frame[-(HASH_SIZE + 1):-1]
                cont_flag = frame[-1] == ord('1')
                if hash_hex(payload) == msg_hash:
                    try:_send(self.sock, b'~1~')
                    except:pass
                else:
                    try:_send(self.sock, b'~0~')
                    except:pass
                    continue
                self.router_queue.append((MID, TID, payload, cont_flag))
    def send(self, data, TID=None, PICKLE=True, timeout=5.0):
        if self.sock==None:raise RuntimeError("Not connected")
        payload_hex = serialize(data, PICKLE=PICKLE)
        body_bytes = payload_hex
        MID_str = gen_ID()
        if not TID:
            TID = gen_ID()
            while TID in self.threads:
                TID = gen_ID()
        TID_str = TID
        if TID_str not in self.threads:
            self.threads.append(TID_str)
        MID_b = util.str_to_bytes(MID_str)
        TID_b = util.str_to_bytes(TID_str)
        if len(MID_b) != ID_LEN or len(TID_b) != ID_LEN:raise ValueError("ID length mismatch")
        chunks = []
        offset = 0
        available_body = self.chunk_size - (ID_LEN + ID_LEN + HASH_SIZE + 3)
        total_len = len(body_bytes)
        while offset < total_len:
            end = min(offset + available_body, total_len)
            chunks.append(body_bytes[offset:end])
            offset = end
        prepared = []
        for i, segment in enumerate(chunks):
            segment_b = util.str_to_bytes(segment)
            seg_hash = util.str_to_bytes(hash_hex(segment_b))
            cont_flag = b'1' if i < len(chunks) - 1 else b'0'
            msg = b'~' + MID_b + TID_b + segment_b + seg_hash + cont_flag + b'~'
            prepared.append(msg)
        for msg in prepared:
            retries = self.max_retries
            while retries > 0:
                self.status = None
                with self.SEND_LOCK:_send(self.sock, msg)
                deadline = time.time() + timeout
                while time.time() < deadline:
                    ack = self.status
                    if ack in (0, 1):break
                    time.sleep(0)
                if ack == 1:break
                retries -= 1
                if retries == 0:return False
        return True
    @property
    def NEW_DATA(self, TID=None):
        if not TID:return len(self.recv_queue)>0
        queue=self.recv_queue.copy()
        for tid, _ in queue:
            if TID and tid!=TID:continue
            return True
        return False
    def router(self):
        while True:
            time.sleep(GENERAL_DELAY())
            now = time.time()
            if len(self.router_queue)<=self.router_cursor:continue
            if self.router_cursor > 500:
                self.router_queue = self.router_queue[self.router_cursor:]
                self.router_cursor = 0
            for key, t0 in list(self.cont_queue_time.items()):
                if now - t0 > 30:
                    self.cont_queue.pop(key, None)
                    self.cont_queue_time.pop(key, None)
            if self.router_cursor < len(self.router_queue):
                MID, TID, payload, cont_flag = self.router_queue[self.router_cursor]
                self.router_cursor += 1
            else:continue
            key = (MID, TID)
            if cont_flag:
                if key not in self.cont_queue:self.cont_queue[key] = payload
                else:self.cont_queue[key] += payload
                self.cont_queue_time[key] = now
            else:
                if key in self.cont_queue:
                    full_payload = self.cont_queue.pop(key) + payload
                    self.cont_queue_time.pop(key, None)
                else:full_payload = payload
                self.recv_queue.append((TID,full_payload))
    def recv(self, TID=None, PICKLE=True, blocking=True, timeout=-1):
        TID=util.str_to_bytes(TID)
        if blocking:
            stime = time.time()
            while timeout == -1 or time.time() - stime < timeout:
                if self.NEW_DATA:
                    data = self.recv(TID=TID, PICKLE=PICKLE, blocking=False)
                    if data!=None:
                        return data
                time.sleep(GENERAL_DELAY())
            return None
        _len=len(self.recv_queue)
        for x in range(_len):
            tid,_ = self.recv_queue[x]
            if TID and tid!=TID:continue
            _,msg=self.recv_queue.pop(x)
            data=deserialize(msg,PICKLE=PICKLE)
            return data