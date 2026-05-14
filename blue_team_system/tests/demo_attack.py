"""
DEMO ATTACK SCRIPT — Day 5
Run this during the live presentation to simulate a real attack scenario.
Member B's monitoring engine should detect and alert on all of these.
"""
import sys
import os
import shutil
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

DEMO_FOLDER = "demo_target"

def setup_demo_folder():
    if os.path.exists(DEMO_FOLDER):
        shutil.rmtree(DEMO_FOLDER)
    os.makedirs(DEMO_FOLDER)
    files = [
        "report_q3.docx",
        "employee_data.csv",
        "project_plan.xlsx",
        "source_code.py",
        "config.json",
    ]
    for name in files:
        with open(os.path.join(DEMO_FOLDER, name), 'w') as f:
            f.write(f"Sensitive content of {name}\n" * 20)
    print(f"[DEMO] Created {len(files)} target files in '{DEMO_FOLDER}'")

def simulate_ransomware_rename():
    print("\n[DEMO] === Simulating ransomware bulk rename ===")
    for filename in os.listdir(DEMO_FOLDER):
        src = os.path.join(DEMO_FOLDER, filename)
        dst = os.path.join(DEMO_FOLDER, filename + ".locked")
        os.rename(src, dst)
        print(f"  Renamed: {filename} -> {filename}.locked")
        time.sleep(0.3)

def simulate_bulk_delete():
    print("\n[DEMO] === Simulating bulk file deletion ===")
    for filename in os.listdir(DEMO_FOLDER):
        path = os.path.join(DEMO_FOLDER, filename)
        os.remove(path)
        print(f"  Deleted: {filename}")
        time.sleep(0.2)

def simulate_honeypot_access():
    print("\n[DEMO] === Simulating honeypot access ===")
    from core.honeypot import create_honeypots, check_honeypot_access
    honeypot_folder = os.path.join(DEMO_FOLDER, "honeypots")
    files = create_honeypots(honeypot_folder)
    # access the first honeypot file
    target = files[0]
    print(f"  Accessing honeypot: {os.path.basename(target)}")
    with open(target, 'r') as f:
        _ = f.read()
    alert = check_honeypot_access(target)
    if alert:
        print(f"  [ALERT FIRED] {alert['severity']}: {alert['message']}")

def simulate_brute_force():
    print("\n[DEMO] === Simulating brute force login ===")
    from core.user_profiles import create_profile, verify_profile
    create_profile("demo_victim", "realpassword123", role="user")
    attempts = ["password", "123456", "admin", "letmein", "qwerty"]
    for attempt in attempts:
        success, _ = verify_profile("demo_victim", attempt, dev_mode=True)
        print(f"  Attempt '{attempt}': {'SUCCESS' if success else 'FAILED'}")
        time.sleep(0.4)
    # cleanup
    import json
    profiles_file = "auth_profiles.json"
    if os.path.exists(profiles_file):
        with open(profiles_file, 'r') as f:
            profiles = json.load(f)
        if "demo_victim" in profiles:
            del profiles["demo_victim"]
        with open(profiles_file, 'w') as f:
            json.dump(profiles, f, indent=2)

def cleanup():
    if os.path.exists(DEMO_FOLDER):
        shutil.rmtree(DEMO_FOLDER)
    if os.path.exists(".honeypot_registry"):
        os.remove(".honeypot_registry")
    print("\n[DEMO] Cleanup complete.")

if __name__ == "__main__":
    print("=" * 60)
    print("  BLUE TEAM SYSTEM — LIVE ATTACK DEMO")
    print("=" * 60)
    setup_demo_folder()
    time.sleep(1)
    simulate_honeypot_access()
    time.sleep(1)
    simulate_brute_force()
    time.sleep(1)
    setup_demo_folder()
    simulate_ransomware_rename()
    time.sleep(1)
    simulate_bulk_delete()
    cleanup()
    print("\n[DEMO] All attack scenarios complete.")
    print("=" * 60)