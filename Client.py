import Watcher, time, Network, os, Encryption, util, socket, getpass, hashlib, random, traceback, zipfile, tempfile, shutil, threading, subprocess, sys
from concurrent.futures import ThreadPoolExecutor
if os.name == "nt":CLEAR=lambda:subprocess.run('cls', shell=True)
elif os.name == "posix":CLEAR=lambda:subprocess.run('clear', shell=True)
CLEAR()
enc=Encryption
DEBUG=True
ROOT=os.path.expanduser('~')
SHARED = ROOT + os.sep + 'Shared - Client'
threading.Thread(target=Watcher.main,kwargs={'PATH': SHARED, 'cache_file': '.client_index'}).start()
try:
    if '--new' in sys.argv:raise Exception
    CA = [enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'CA_pub.pem'),enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'CA_cert.pem')]
except:
    path = input('ClientData path: ')
    tmp = tempfile.mkdtemp()
    zipfile.ZipFile(path).extractall(tmp)
    path = tmp + os.sep + os.path.basename(path)
    _pub_key = enc.load_key(path + os.sep + 'CA_pub.pem')
    for x in os.listdir(path):
        if x.endswith('.sig'):continue
        with open(path + os.sep + x, 'rb') as f:data = f.read()
        with open(path + os.sep + x + '.sig', 'rb') as f:sig = f.read()
        if not enc.verify(_pub_key, data, sig):exit('Invalid key')
    os.makedirs(ROOT + os.sep + 'Client - Keys', exist_ok=True)
    shutil.copy2(path + os.sep + 'CA_pub.pem',ROOT + os.sep + 'Client - Keys' + os.sep + 'CA_pub.pem')
    shutil.copy2(path + os.sep + 'CA_cert.pem',ROOT + os.sep + 'Client - Keys' + os.sep + 'CA_cert.pem')
    CA = [enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'CA_pub.pem'),enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'CA_cert.pem')]
IP=None
for x in socket.getaddrinfo(socket.gethostname(), None):
    _ip = x[4][0]
    if x[0] != socket.AF_INET:continue
    if _ip.startswith("127."):continue
    IP = _ip;break
ip=input(f'Client IP (defualt is {IP})')
if ip:IP=ip
sip=input(f'Server IP (defualt is loopback {IP}): ')
if not sip:sip=IP
cport=input('Client port (defualt is 7443): ')
try:
    cport=int(cport)
    if cport<1024:cport=''
    if cport>65535:cport=''
except:cport=''
if not cport:cport=7443
sport=input('Server port (defualt is 8443): ')
try:
    sport=int(sport)
    if sport<1024:sport=''
    if sport>65535:sport=''
except:sport=''
if not sport:sport=7443
client = Network.Client(client_ip=IP,client_port=cport,server_ip=sip,server_port=sport)
username = input('Username: ')
password = util.str_to_bytes(enc.hash_password(username + getpass.getpass()))
try:
    prv_key = enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'PRV_KEY.der',password=password)
    enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'PUB_KEY.der')
    with open(ROOT + os.sep + 'Client - Keys' + os.sep + 'PUB_KEY.der', 'rb') as f:pub_key = f.read()
except:
    enc.create_auth_keys(ROOT + os.sep + 'Client - Keys' + os.sep + 'PRV_KEY.der',ROOT + os.sep + 'Client - Keys' + os.sep + 'PUB_KEY.der',password=password)
    prv_key = enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'PRV_KEY.der',password=password)
    enc.load_key(ROOT + os.sep + 'Client - Keys' + os.sep + 'PUB_KEY.der')
    with open(ROOT + os.sep + 'Client - Keys' + os.sep + 'PUB_KEY.der', 'rb') as f:pub_key = f.read()
def request(request_type: bytes, **kwargs):
    global request_num
    try:
        request_num+=1
        print('\r\033[K' + f'Auth for request # {request_num} Request type: {request_type}', end='', flush=True)
        client.send(request_type, PICKLE=False)
        TID=client.threads[-1]
        key_data=enc.gen_key_bytes()
        resp=client.recv(TID)
        if not enc.verify(CA[0],resp['msg'],resp['sign']):print('\r\033[K', end='', flush=True);return
        skey_data=resp['msg']
        client.send(key_data['public']+skey_data[:32]+skey_data[32:],TID,False)
        aes_key=enc.create_aes_key(key_data['private'],skey_data[:32],skey_data[32:])
        data=client.recv(TID)
        token=enc.aes_decrypt(aes_key,data['msg'])
        if not enc.verify(CA[0],data['msg'],data['sign']):print('\r\033[K', end='', flush=True);return
        client.send(username,TID,False)
        _=enc.sign(prv_key,token)
        _=enc.aes_encrypt(aes_key,_)
        client.send(_,TID,False)
        resp=client.recv(TID,False)
        if resp==b'0':exit('Connection Rejected!')
        if resp==b'2':
            client.send(enc.aes_encrypt(aes_key,pub_key),TID,False)
            resp=client.recv(TID,False)
            if resp==b'0':print('\r\033[K', end='', flush=True);return
        # process request
        print('\r\033[K' + f'Processing request # {request_num} Request type: {request_type}', end='', flush=True)
        if request_type==b'JSON':
            out=[]
            while True:
                data=client.recv(TID,timeout=30)
                if not data:break
                if not enc.verify(CA[0],data['msg'],data['sign']):print('\r\033[K', end='', flush=True);return
                out.append(data['msg'])
                if data['end']:break
            for x in range(len(out)):out[x]=util.bytes_to_str(enc.aes_decrypt(aes_key,out[x]))
            out=Network.deserialize(''.join(out))
            print('\r\033[K', end='', flush=True)
            if not isinstance(out,dict):return
            return out
        if request_type==b'DOWN':
            path=kwargs['path']
            print('\r\033[K' + f'Processing request # {request_num} Request type: {request_type} Path: {path[-25:]}', end='', flush=True)
            if client.recv(TID,False,timeout=30)!=b'1':print('\r\033[K', end='', flush=True);return
            client.send(enc.aes_encrypt(aes_key,util.str_to_bytes(path.replace(os.sep,'/'))),TID,False)
            data=client.recv(TID,timeout=30)
            if not enc.verify(CA[0],data['msg'],data['sign']):print('\r\033[K', end='', flush=True);return
            Hash=enc.aes_decrypt(aes_key,data['msg'])
            out=b''
            while True:
                data=client.recv(TID,False,timeout=15)
                if not data:break
                out+=enc.aes_decrypt(aes_key,data)
            if hashlib.sha512(out).digest()==Hash:
                path=SHARED+os.sep+path
                os.makedirs(os.path.dirname(path),exist_ok=True)
                if out==b'':
                    try:os.remove(path)
                    except:pass
                else:
                    with open(path+'.tmp','wb') as f:f.write(out);f.flush();os.fsync(f.fileno())
                    os.replace(path+'.tmp',path)
        if request_type == b'UP':
            path = kwargs['path']
            print('\r\033[K' + f'Processing request # {request_num} Request type: {request_type} Path: {path[-25:]}', end='', flush=True)
            try:
                with open(SHARED+os.sep+path,'rb') as f:data=f.read()
            except:data=b''
            if client.recv(TID, False, timeout=30) != b'1':print('\r\033[K', end='', flush=True);return
            client.send(enc.aes_encrypt(aes_key, util.str_to_bytes(path.replace(os.sep,'/'))), TID, False)
            file_hash = hashlib.sha512(data).digest()
            msg = enc.aes_encrypt(aes_key, file_hash)
            client.send(msg, TID, False)
            start = 0
            chunk_size = 65536
            while start < len(data):
                chunk = data[start:start + chunk_size]
                start += chunk_size
                enc_chunk = enc.aes_encrypt(aes_key, chunk)
                client.send(enc_chunk, TID, False)
    except Exception as e:traceback.print_exception(e)
while not Watcher.READY:time.sleep(5)
pool = ThreadPoolExecutor(max_workers=5)
request_num=0
request(b'auth')
DELETED = ''
last_index = None
last_activity = 0

while True:
    local_index = Watcher.INDEX()
    remote_index = request(b'JSON')
    state = (tuple(local_index.items()), tuple(remote_index.items()))
    if state == last_index:
        last_activity += 1
        waited = 0
        while waited < min(last_activity, 12):
            time.sleep(2.5)
            waited += 1
            new_local = Watcher.INDEX()
            if new_local != local_index:last_activity = 0;break
        continue
    last_activity = 0
    last_index = state
    try:
        paths = list(local_index.keys() | remote_index.keys())
    except:
        time.sleep(5)
        continue
    random.shuffle(paths)
    for path in paths:
        local_hash, local_ts = local_index.get(path, (DELETED, 0))
        remote_hash, remote_ts = remote_index.get(path, (DELETED, 0))
        if local_hash == remote_hash:
            continue
        if local_ts > remote_ts:request(b'UP',path=path)
        else:request(b'DOWN',path=path)
    time.sleep(2.5)