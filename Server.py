import Watcher, time, Network, os, Encryption, shutil, util, getpass, subprocess, hashlib, tempfile, threading, sys
subprocess.run('clear', shell=True)
enc=Encryption
DEBUG=False
ROOT=os.path.expanduser('~')
SHARED=ROOT + '/Shared - Server'
def create_new_keys():
    root = ROOT + '/Server - Keys'
    shutil.rmtree(root, ignore_errors=True)
    pw=util.str_to_bytes(getpass.getpass('CA PASSWORD: '))
    os.makedirs(ROOT + '/Server - Keys/Client - Keys', exist_ok=True)
    enc.create_ca(root + '/CA_prv.pem', root + '/CA_pub.pem', root + '/CA_cert.pem', "Daniel's FTP server v2", password=pw)
    CA=load_CA(password=pw)
    enc.create_https_keys(prv_path=root + '/HTTPS_prv.pem', pub_path=root + '/HTTPS_pub.pem', cert_path=root + '/HTTPS_cert.pem', common_name="Daniel's FTP server v2", CA_prv=root + '/CA_prv.pem', CA_cert=root + '/CA_cert.pem', CA_PW=pw)
    _tmp=tempfile.mkdtemp()
    os.makedirs(_tmp+'/ClientData')
    tmp=_tmp+'/ClientData'
    shutil.copy2(root + '/CA_pub.pem', tmp+'/CA_pub.pem')
    shutil.copy2(root + '/CA_cert.pem', tmp+'/CA_cert.pem')
    for x in os.listdir(tmp):
        with open(tmp+'/' + x, 'rb') as f:data=f.read()
        with open(tmp+'/' + x + '.sig','wb') as f:f.write(enc.sign(CA[0],data))
    shutil.make_archive(ROOT+'/ClientData','zip',_tmp,'ClientData')
    os.rename(ROOT+'/ClientData.zip',ROOT+'/ClientData')
    shutil.rmtree(_tmp,True)
    return CA
def load_CA(password=b''):
    out=[]
    if password==b'':password=util.str_to_bytes(getpass.getpass('CA PASSWORD: '))
    out.append(enc.load_key(ROOT + '/Server - Keys/CA_prv.pem', log=DEBUG, password=password))
    out.append(enc.load_key(ROOT + '/Server - Keys/CA_pub.pem', log=DEBUG))
    out.append(enc.load_key(ROOT + '/Server - Keys/CA_cert.pem', log=DEBUG))
    return out
def on_new_thread(CID, TID):
    global PW
    request_type=server.recv(CID, TID, False, timeout=5)
    if not request_type:return
    key_data=enc.gen_key_bytes()
    salt=enc.random.randbytes(16)
    msg=key_data['public'] + salt
    sig=enc.sign(CA[0], msg)
    server.send({'msg':msg, 'sign':sig}, CID, TID)
    resp=server.recv(CID, TID, False, timeout=5)
    if not resp:return
    client_pub = resp[:32]
    if resp[32:64]!=key_data['public']:return
    if resp[64:]!=salt:return
    aes_key=enc.create_aes_key(key_data['private'], client_pub, salt)
    token=enc.gen_nonce()
    msg=enc.aes_encrypt(aes_key, token)
    sig=enc.sign(CA[0], msg)
    server.send({'msg':msg, 'sign':sig}, CID, TID)
    username=util.bytes_to_str(server.recv(CID, TID, False, timeout=5))
    if not username:return
    resp=server.recv(CID, TID, False, timeout=5)
    if not resp:return
    sig=enc.aes_decrypt(aes_key, resp)
    valid=False
    for x in PW:
        if x!=username:continue
        if enc.verify(PW[x], token, sig):valid=True;break
    if valid:server.send(b'1', CID, TID, False)
    else:
        # subprocess.run('clear', shell=True)
        print('='*10 + ' NEW CLIENT AUTH! ' + '='*10)
        if input(f'A new client is trying to authenticate, do you accept?\nUsername: {username}\n')[0].lower()=='y':
            valid=True
            server.send(b'2', CID, TID, False)
            pw=server.recv(CID, TID, False, timeout=5)
            if not pw:return
            pw=enc.aes_decrypt(aes_key, pw)
            try:_pw=enc.load_key(pw)
            except:server.send(b'0', CID, TID, False);return
            if enc.verify(_pw, token, sig):
                path=ROOT + '/Server - Keys/Client - Keys/' + Network.gen_ID() + ' ~ ' + username + '.der'
                with open(path, 'wb') as f:f.write(pw)
                try:PW[username]=enc.load_key(path)
                except:server.send(b'0', CID, TID, False);return
                server.send(b'1', CID, TID, False)
            else:server.send(b'0', CID, TID, False);return
        else:server.send(b'0', CID, TID, False);return
    # process request
    if request_type==b'JSON':
        data=Network.serialize(Watcher.INDEX())
        start=0
        chunk_size=65536
        while start<len(data):
            chunk=data[start:start + chunk_size]
            start += chunk_size
            msg=enc.aes_encrypt(aes_key, chunk)
            sig=enc.sign(CA[0], msg)
            server.send({'msg':msg, 'sign':sig, 'end':start>=len(data)}, CID, TID)
    if request_type==b'DOWN':
        server.send(b'1', CID, TID, False)
        path=server.recv(CID, TID, False, timeout=5)
        if not path:return
        path=util.bytes_to_str(enc.aes_decrypt(aes_key, path))
        try:
            with open(SHARED + '/' + path, 'rb') as f:data=f.read()
        except:data=b''
        msg=enc.aes_encrypt(aes_key, hashlib.sha512(data).digest())
        sig=enc.sign(CA[0], msg)
        server.send({'msg':msg, 'sign':sig}, CID, TID)
        start=0
        chunk_size=65536
        while start<len(data):
            chunk=data[start:start + chunk_size]
            start += chunk_size
            msg=enc.aes_encrypt(aes_key, chunk)
            server.send(msg, CID, TID, False)
    if request_type == b'UP':
        server.send(b'1', CID, TID, False)
        path = server.recv(CID, TID, False, timeout=5)
        if not path:return
        path = util.bytes_to_str(enc.aes_decrypt(aes_key, path))
        if path.startswith('/'):return
        data = server.recv(CID, TID, False, timeout=5)
        if not data:return
        expected_hash = enc.aes_decrypt(aes_key, data)
        out = b''
        num=0
        while True:
            chunk = server.recv(CID, TID, False, timeout=15)
            num += 1
            if not chunk:break
            out  +=  enc.aes_decrypt(aes_key, chunk)
        if hashlib.sha512(out).digest() != expected_hash:return
        if out==b'':
            try:os.remove(SHARED + '/' + path)
            except:pass
        else:
            os.makedirs(os.path.dirname(SHARED + '/' + path), exist_ok=True)
            with open(SHARED + '/' + path + '.tmp', 'wb') as f:
                f.write(out)
                f.flush()
                os.fsync(f.fileno())
            os.replace(SHARED + '/' + path + '.tmp', SHARED + '/' + path)
if util.test_main('SERVER: MAIN'):
    threading.Thread(target=Watcher.main, kwargs={'PATH':SHARED,'cache_file':'.server_index'}).start()
    if '--new' in sys.argv:
        input('Creating new keys (press enter)')
        CA=create_new_keys()
    else:CA=load_CA(password=util.str_to_bytes(getpass.getpass('CA PASSWORD: ')))
    server=Network.Server(host_port=8443, max_retries=10, prv_key=ROOT + '/Server - Keys/HTTPS_prv.pem', cert_key=ROOT + '/Server - Keys/HTTPS_cert.pem')
    PW=dict()
    for x in os.listdir(ROOT + '/Server - Keys/Client - Keys'):
        try:
            PW[x[x.find(' ~ ')+3:-4]]=(enc.load_key(ROOT + '/Server - Keys/Client - Keys/' + x))
        except:
            try:os.remove(ROOT + '/Server - Keys/Client - Keys/' + x)
            except:pass
    while not Watcher.READY:time.sleep(5)
    server.on_new_thread=on_new_thread
    subprocess.run('clear', shell=True)
    time.sleep(1)
    server.start()
    print('Ready')
    while True:time.sleep(5)