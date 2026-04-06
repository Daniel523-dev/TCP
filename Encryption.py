from cryptography.x509 import load_der_x509_certificate, load_pem_x509_certificate, Name, NameAttribute, CertificateBuilder, random_serial_number, BasicConstraints
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_der_public_key, load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
import argon2.low_level, os, threading, util, collections, warnings
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
HASH=hashes.SHA512
AES_NONCE=16
HKDF_OUTPUT_LEN=64
PSS_PAD = padding.PSS(mgf=padding.MGF1(HASH()),salt_length=padding.PSS.MAX_LENGTH)
class Random:
    def __init__(self,max_size=16 * 1024 * 1024,chunk_size=4096):
        self.max_size = max_size
        self.key_cache_size=256
        self.chunk_size = chunk_size
        self.buffer = collections.deque()
        self.x25519 = []
        self.ed25519 = []
        self.x25519_num = 0
        self.ed25519_num = 0
        self.size = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.condition = threading.Condition(self.lock)
        self.thread = threading.Thread(target=self._worker, daemon=True)
        self.thread.start()
    def _gen_ed25519(self):
        return ed25519.Ed25519PrivateKey.generate()
    def _gen_x25519(self):
        private = x25519.X25519PrivateKey.generate()
        public = private.public_key()
        return {'private':private,'public':public.public_bytes_raw()}
    def _worker(self):
        while not self.stop_event.is_set():
            with self.condition:
                while self.size > self.max_size*0.5 and not self.stop_event.is_set():
                    self.condition.wait()
                while self.size < self.max_size and not self.stop_event.is_set():
                    data = os.urandom(self.chunk_size)
                    self.buffer.append(data)
                    self.size += len(data)
                while self.x25519_num > self.key_cache_size*0.5 and not self.stop_event.is_set():
                    self.condition.wait()
                while self.x25519_num < self.key_cache_size and not self.stop_event.is_set():
                    data = self._gen_x25519()
                    self.x25519.append(data)
                    self.x25519_num += 1
                while self.ed25519_num > self.key_cache_size*0.5 and not self.stop_event.is_set():
                    self.condition.wait()
                while self.ed25519_num < self.key_cache_size and not self.stop_event.is_set():
                    data = self._gen_ed25519()
                    self.ed25519.append(data)
                    self.ed25519_num += 1
    def randbytes(self, n: int) -> bytes:
        with self.condition:
            out = bytearray()
            while n > 0:
                if not self.buffer:break
                chunk = self.buffer[0]
                if len(chunk) <= n:
                    out.extend(chunk)
                    self.buffer.popleft()
                    self.size -= len(chunk)
                    n -= len(chunk)
                else:
                    out.extend(chunk[:n])
                    self.buffer[0] = chunk[n:]
                    self.size -= n
                    n = 0
            if self.size <= self.max_size*0.5:self.condition.notify()
        if n > 0:out.extend(os.urandom(n))
        return bytes(out)
    def gen_ed25519(self):
        with self.condition:
            if len(self.ed25519)==0:return self._gen_ed25519()
            return self.ed25519.pop(0)
    def gen_x25519(self):
        with self.condition:
            if len(self.x25519)==0:return self._gen_x25519()
            return self.x25519.pop(0)
    def stop(self):
        self.stop_event.set()
        with self.condition:
            self.condition.notify_all()
        self.thread.join()
random=Random()
KEY_EXPONENT=2**16+1
def gen_salt():return random.randbytes(16)
def gen_nonce():return random.randbytes(128)
def gen_key_bytes():return random.gen_x25519()
def hash_password(password: str | bytes, salt: bytes=b' '*32, security=0, cores=2, time_cost=-1,mem_cost=-1) -> dict:
    cost=[None,None]
    if security==-2:cost=[1,2**12]
    if security==-1:cost=[2,2**13]
    if security==0:cost=[3,2**14*1.5]
    if security==1:cost=[4,2**15]
    if security==2:cost=[5,2**16]
    if time_cost in range(1,10):cost[0]=time_cost
    if mem_cost in range(10,20):cost[1]=2**mem_cost
    if mem_cost>=2**10:cost[1]=mem_cost
    if None in cost:raise ValueError('Invalid value for security')
    hash_bytes = argon2.low_level.hash_secret_raw(secret=util.str_to_bytes(password),salt=salt,time_cost=cost[0],memory_cost=round(cost[1]),parallelism=min(max(cores,1),6),hash_len=256,type=argon2.low_level.Type.ID)
    return hash_bytes.hex()
class CryptoError(Exception):pass
class InvalidKeyError(CryptoError):pass
def load_key(data: bytes | str | list, password=None, log=False):
    if isinstance(data,(list,tuple)):
        out=[]
        for x in data:
            out.append(load_key(x,password=password,log=log))
        return out
    if isinstance(data,str):
        try:
            with open(data,'rb') as f:data=f.read()
        except:data=util.str_to_bytes(data)
    try:return load_pem_x509_certificate(data)
    except:pass
    try:return load_der_x509_certificate(data)
    except:pass
    try:return load_pem_private_key(data, password=password)
    except:pass
    try:return load_pem_private_key(data, password=None)
    except:pass
    try:return load_der_private_key(data, password=password)
    except:pass
    try:return load_der_private_key(data, password=None)
    except:pass
    try:return load_pem_public_key(data)
    except:pass
    try:return load_der_public_key(data)
    except Exception as e:raise InvalidKeyError('All loading attempts failed!')
def create_ca(prv_path: str, pub_path: str, cert_path: str, name: str, password: bytes):
    ca_key = ed25519.Ed25519PrivateKey.generate()
    subject = issuer = Name([NameAttribute(NameOID.COMMON_NAME, name)])
    CA_cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.now() - timedelta(days=1))
        .not_valid_after(datetime.now() + timedelta(days=3650))
        .add_extension(BasicConstraints(ca=True, path_length=None),critical=True).sign(private_key=ca_key,algorithm=None))
    os.makedirs(os.path.dirname(prv_path), exist_ok=True)
    os.makedirs(os.path.dirname(pub_path), exist_ok=True)
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(prv_path, "wb") as f:f.write(ca_key.private_bytes(encoding=serialization.Encoding.PEM if prv_path.endswith(".pem") else serialization.Encoding.DER,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=serialization.BestAvailableEncryption(password)))
    with open(pub_path, "wb") as f:f.write(ca_key.public_key().public_bytes(encoding=serialization.Encoding.PEM if pub_path.endswith(".pem") else serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(cert_path, "wb") as f:f.write(CA_cert.public_bytes(serialization.Encoding.PEM if cert_path.endswith(".pem") else serialization.Encoding.DER))
def create_https_keys(prv_path,pub_path,cert_path,CA_prv,CA_cert,common_name,days_valid=3650,CA_PW=b'',password=b''):
    server_key = ed25519.Ed25519PrivateKey.generate()
    server_public_key = server_key.public_key()
    subject = Name([NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert_builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(load_key(CA_cert).subject)
        .public_key(server_public_key)
        .serial_number(random_serial_number())
        .not_valid_before(datetime.now() - timedelta(days=1))
        .not_valid_after(datetime.now() + timedelta(days=days_valid))
        .add_extension(BasicConstraints(ca=False, path_length=None),critical=True))
    ca_key = load_key(CA_prv, password=CA_PW)
    server_cert = cert_builder.sign(private_key=ca_key,algorithm=None)
    if password:algo = serialization.BestAvailableEncryption(password)
    else:algo = serialization.NoEncryption()
    os.makedirs(os.path.dirname(prv_path), exist_ok=True)
    os.makedirs(os.path.dirname(pub_path), exist_ok=True)
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(prv_path, "wb") as f:f.write(server_key.private_bytes(encoding=serialization.Encoding.PEM if prv_path.endswith(".pem") else serialization.Encoding.DER,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=algo))
    with open(pub_path, "wb") as f:f.write(server_key.public_key().public_bytes(encoding=serialization.Encoding.PEM if pub_path.endswith(".pem") else serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(cert_path, "wb") as f:f.write(server_cert.public_bytes(serialization.Encoding.PEM if cert_path.endswith(".pem") else serialization.Encoding.DER))
def create_key_triplet(*,prv_path: str,pub_path: str,cert_path: str,common_name: str,days_valid: int = 3650,CA_prv: str = None,CA_cert: str = None,CA_PW=None,password=None):
    key = ed25519.Ed25519PrivateKey.generate()
    subject = Name([NameAttribute(NameOID.COMMON_NAME, common_name)])
    if CA_prv and CA_cert:
        ca_key = load_key(CA_prv, password=CA_PW)
        ca_cert = load_key(CA_cert)
        issuer = ca_cert.subject
        signer_key = ca_key
    else:
        issuer = subject
        signer_key = key
    builder = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(random_serial_number())
        .not_valid_before(datetime.now() - timedelta(days=1))
        .not_valid_after(datetime.now() + timedelta(days=days_valid))
        .add_extension(BasicConstraints(ca=False, path_length=None),critical=True))
    cert = builder.sign(private_key=signer_key,algorithm=None)
    if password:algo = serialization.BestAvailableEncryption(password)
    else:algo = serialization.NoEncryption()
    os.makedirs(os.path.dirname(prv_path), exist_ok=True)
    os.makedirs(os.path.dirname(pub_path), exist_ok=True)
    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    with open(prv_path, "wb") as f:f.write(key.private_bytes(encoding=serialization.Encoding.PEM if prv_path.endswith(".pem") else serialization.Encoding.DER,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=algo))
    with open(pub_path, "wb") as f:f.write(key.public_key().public_bytes(encoding=serialization.Encoding.PEM if pub_path.endswith(".pem") else serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(cert_path, "wb") as f:f.write(cert.public_bytes(serialization.Encoding.PEM if cert_path.endswith(".pem") else serialization.Encoding.DER))
def create_auth_keys(prv_path,pub_path,password=b''):
    private_key = random.gen_ed25519()
    if password:algo=serialization.BestAvailableEncryption(password=password)
    else:algo=serialization.NoEncryption()
    with open(prv_path,'wb') as f:f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM if prv_path.endswith('.pem') else serialization.Encoding.DER,format=serialization.PrivateFormat.PKCS8,encryption_algorithm=algo))
    with open(pub_path,'wb') as f:f.write(private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM if pub_path.endswith('.pem') else serialization.Encoding.DER,format=serialization.PublicFormat.SubjectPublicKeyInfo))
def create_aes_key(private, peer_public, salt):
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public)
    shared_secret = private.exchange(peer_public_key)
    digest = hashes.Hash(HASH())
    digest.update(salt)
    salt = digest.finalize()
    hkdf = HKDF(algorithm=HASH(),length=32,salt=salt)
    return hkdf.derive(shared_secret)
def verify_cert(cert, ca_cert):
    ca_public_key = ca_cert.public_key()
    try:ca_public_key.verify(cert.signature,cert.tbs_certificate_bytes);return True
    except Exception:return False
def aes_encrypt(aes_key, plaintext):
    nonce = random.randbytes(AES_NONCE)
    return nonce + AESGCM(aes_key).encrypt(nonce, plaintext, None)
def aes_decrypt(aes_key, data):
    return AESGCM(aes_key).decrypt(data[:AES_NONCE], data[AES_NONCE:], None)
def rsa_encrypt(*args,**kwargs):
    warnings.warn('Use Ed25519')
def rsa_decrypt(*args,**kwargs):
    warnings.warn('Use Ed25519')
def sign(private_key, data: bytes) -> bytes:return private_key.sign(data)
def verify(public_key, data: bytes, signature: bytes) -> bool:
    try:public_key.verify(signature, data);return True
    except InvalidSignature:return False