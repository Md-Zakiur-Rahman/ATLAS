#!/usr/bin/env python3
"""
Day 1 Integration Test
Verify all components are working correctly
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_database():
    """Test database initialization and operations"""
    print("\n[TEST] Testing Database Manager...")
    
    from database.db_manager import DatabaseManager
    
    # Initialize
    db = DatabaseManager("logs/test_events.db")
    
    # Log event
    event_id = db.log_event("TEST_EVENT", "LOW", {"test": "data"})
    print(f"  ✓ Logged event with ID: {event_id}")
    
    # Log threat
    threat_id = db.log_threat("TEST_THREAT", "MEDIUM", process_name="test.exe")
    print(f"  ✓ Logged threat with ID: {threat_id}")
    
    # Log auth
    auth_id = db.log_auth_attempt("testuser", True, "TEST_DEVICE")
    print(f"  ✓ Logged auth attempt with ID: {auth_id}")
    
    # Fetch events
    events = db.get_events(limit=10)
    print(f"  ✓ Retrieved {len(events)} events")
    
    # Fetch threats
    threats = db.get_threats(limit=10)
    print(f"  ✓ Retrieved {len(threats)} threats")
    
    # Get stats
    stats = db.get_event_stats()
    print(f"  ✓ Stats - Total Events: {stats['total_events']}, Critical Threats: {stats['critical_threats']}")
    
    # Export CSV
    db.export_events_csv("logs/test_export.csv")
    print(f"  ✓ Exported events to CSV")
    
    # Cleanup
    os.remove("logs/test_events.db")
    os.remove("logs/test_export.csv")
    
    return True

def test_gui_imports():
    """Test GUI imports"""
    print("\n[TEST] Testing GUI Imports...")
    
    try:
        import customtkinter as ctk
        print(f"  ✓ CustomTkinter version: {ctk.__version__}")
        
        from dashboard.app import BlueTeamApp
        print("  ✓ BlueTeamApp imported successfully")
        
        return True
    except Exception as e:
        print(f"  ✗ GUI import error: {e}")
        return False

def test_dependencies():
    """Test all required dependencies"""
    print("\n[TEST] Testing Dependencies...")
    
    dependencies = [
        'customtkinter',
        'cryptography',
        'watchdog',
        'psutil',
        'matplotlib',
        'pandas',
    ]
    
    missing = []
    for dep in dependencies:
        try:
            __import__(dep)
            print(f"  ✓ {dep}")
        except ImportError:
            print(f"  ✗ {dep} - MISSING")
            missing.append(dep)
    
    return len(missing) == 0

def main():
    print("=" * 60)
    print("   BLUE TEAM SYSTEM - DAY 1 INTEGRATION TEST")
    print("=" * 60)
    
    all_passed = True
    
    # Test dependencies
    if not test_dependencies():
        print("\n[FAIL] Missing dependencies. Run: pip install -r requirements.txt")
        all_passed = False
    
    # Test database
    try:
        if not test_database():
            all_passed = False
    except Exception as e:
        print(f"  ✗ Database test failed: {e}")
        all_passed = False
    
    # Test GUI imports
    try:
        if not test_gui_imports():
            all_passed = False
    except Exception as e:
        print(f"  ✗ GUI test failed: {e}")
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("   ✅ ALL DAY 1 TESTS PASSED!")
        print("\n   Ready to run: python main.py")
    else:
        print("   ❌ SOME TESTS FAILED - See errors above")
    print("=" * 60 + "\n")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())