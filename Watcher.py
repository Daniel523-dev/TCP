import os
import time
import json
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
SCAN_INTERVAL = 5
DELETED = ""
READY=False
STATE = {}
CACHE_FILE = ''
def hash_file(path):
    try:
        h = hashlib.sha1()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (FileNotFoundError, PermissionError):
        return DELETED
def load_cache():
    global STATE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r") as f:
                STATE = json.load(f)
        except Exception:
            STATE = {}
    else:
        STATE = {}
def save_cache():
    tmp = CACHE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(STATE, f)
    os.replace(tmp, CACHE_FILE)
def emit(rel_path, value):
    STATE[rel_path] = value
    save_cache()
def rel(root, path):return os.path.relpath(path, root)
def scan(root):
    global READY
    seen = set()
    for r, _, files in os.walk(root):
        for name in files:
            try:
                abs_path = os.path.join(r, name)
                rp = rel(root, abs_path)
                seen.add(rp)
                h = hash_file(abs_path)
                now = time.time()
                old = STATE.get(rp)
                if old is None:
                    emit(rp, (h, now))
                    continue
                old_hash = old[0]
                if old_hash != h:
                    emit(rp, (h, now))
            except:pass
    for rp in list(STATE.keys()):
        try:
            if rp not in seen:
                old_hash, _ = STATE[rp]
                if old_hash != DELETED:
                    emit(rp, (DELETED, time.time()))
        except:pass
    READY=True
class Handler(FileSystemEventHandler):
    def __init__(self, root):
        self.root = root
    def process(self, abs_path):
        rp = rel(self.root, abs_path)
        now = time.time()
        h = hash_file(abs_path)
        old = STATE.get(rp)
        if h == DELETED:
            if old is None or old[0] != DELETED:
                emit(rp, (DELETED, now))
            return
        if old and old[0] == h:
            return
        emit(rp, (h, now))
    def on_created(self, event):
        if not event.is_directory:
            self.process(event.src_path)
    def on_modified(self, event):
        if not event.is_directory:
            self.process(event.src_path)
    def on_moved(self, event):
        if not event.is_directory:
            self.process(event.dest_path)
            self.process(event.src_path)
    def on_deleted(self, event):
        if not event.is_directory:
            rp = rel(self.root, event.src_path)
            emit(rp, (DELETED, time.time()))
def INDEX():
    return STATE
def main(PATH,cache_file):
    global READY, CACHE_FILE
    CACHE_FILE=cache_file
    load_cache()
    observer = Observer()
    observer.schedule(Handler(PATH), PATH, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(SCAN_INTERVAL)
            scan(PATH)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()