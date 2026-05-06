from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from time import sleep

from event_bus import publish
from models import EventLog, ThreatLevel


class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        log = EventLog(
            event_type="FILE_CREATED",
            severity=ThreatLevel.LOW,
            details=event.src_path
        )

        publish(log)
        print(f"[+] File Created: {event.src_path}")

    def on_deleted(self, event):
        log = EventLog(
            event_type="FILE_DELETED",
            severity=ThreatLevel.MEDIUM,
            details=event.src_path
        )

        publish(log)
        print(f"[-] File Deleted: {event.src_path}")

    def on_modified(self, event):
        log = EventLog(
            event_type="FILE_MODIFIED",
            severity=ThreatLevel.LOW,
            details=event.src_path
        )

        publish(log)
        print(f"[*] File Modified: {event.src_path}")


observer = Observer()
handler = FileMonitorHandler()

path_to_watch = "D:/ATLAS_TEST"

observer.schedule(handler, path=path_to_watch, recursive=True)

observer.start()

print(f"Monitoring Started on: {path_to_watch}")

try:
    while True:
        sleep(1)

except KeyboardInterrupt:
    observer.stop()

observer.join()