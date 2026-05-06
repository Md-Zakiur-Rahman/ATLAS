from queue import Queue
from threading import Lock

event_queue = Queue()
queue_lock = Lock()

def publish(event):
    with queue_lock:
        event_queue.put(event)

def get_event():
    with queue_lock:
        if not event_queue.empty():
            return event_queue.get()
    return None