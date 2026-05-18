import sys
import os

def main():
    minimized = "--minimized" in sys.argv

    # Init DB on every launch
    from database.db_manager import init_db, verify_chain
    init_db()

    # Verify log chain integrity on startup
    valid, msg = verify_chain()
    if not valid:
        print(f"[STARTUP] WARNING: {msg}")

    # Start Flask remote lock server in background
    from core.biometric_auth import start_flask_server
    start_flask_server(port=5000)

    # Show setup wizard if first run, else go to login
    from core.register import is_registered
    if not is_registered():
        from dashboard.setup_wizard import launch_wizard
        launch_wizard(on_complete=lambda data: _launch_dashboard(minimized))
    else:
        _launch_dashboard(minimized)

def _launch_dashboard(minimized: bool = False):
    from dashboard.app import App
    app = App(minimized=minimized)
    app.mainloop()

if __name__ == "__main__":
    main()