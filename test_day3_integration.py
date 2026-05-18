#!/usr/bin/env python3
"""
Day 3 Integration Test
Verify all components work together
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_database_enhancements():
    """Test new database methods"""
    print("\n[TEST] Testing database enhancements...")
    
    try:
        from database.db_manager import DatabaseManager
        
        db = DatabaseManager("logs/test_day3.db")
        
        # Log some test events
        for i in range(5):
            db.log_event(f"TEST_EVENT_{i}", "LOW", {"test": f"data_{i}"})
        
        # Log encryption
        db.log_file_operation("ENCRYPT", "test.txt", 1024, encrypted=True)
        
        # Get hourly data
        hourly = db.get_events_by_hour(hours=24)
        print(f"  ✓ Hourly events: {len(hourly)} hours with data")
        
        # Get event counts by type
        by_type = db.get_event_count_by_type()
        print(f"  ✓ Events by type: {len(by_type)} types")
        
        # Get encryption stats
        enc_stats = db.get_encryption_stats()
        print(f"  ✓ Encryption stats: {enc_stats['files_encrypted']} files")
        
        # Get threat summary
        threat_summary = db.get_threat_summary()
        print(f"  ✓ Threat summary: {len(threat_summary)} threat types")
        
        # Cleanup
        os.remove("logs/test_day3.db")
        
        return True
    except Exception as e:
        print(f"  ✗ Database test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_pdf_generation():
    """Test PDF report generation"""
    print("\n[TEST] Testing PDF generation...")
    
    try:
        from database.db_manager import DatabaseManager
        from dashboard.pdf_generator import PDFReportGenerator
        
        db = DatabaseManager("logs/test_day3_pdf.db")
        pdf_gen = PDFReportGenerator(db)
        
        # Add some test data
        db.log_event("TEST_EVENT", "HIGH", {"test": "data"})
        db.log_threat("TEST_THREAT", "CRITICAL", process_name="test.exe")
        
        # Generate PDF
        filename = pdf_gen.generate_report(report_type="summary", hours=24)
        
        if os.path.exists(filename):
            size = os.path.getsize(filename)
            print(f"  ✓ PDF generated: {size} bytes")
            os.remove(filename)
        else:
            print(f"  ✗ PDF file not created")
            return False
        
        # Cleanup
        os.remove("logs/test_day3_pdf.db")
        
        return True
    except Exception as e:
        print(f"  ✗ PDF test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_imports():
    """Test all imports"""
    print("\n[TEST] Testing imports...")
    
    try:
        from dashboard.dashboard_tab import DashboardTab
        print("  ✓ DashboardTab")
        
        from dashboard.encrypt_tab import EncryptTab
        print("  ✓ EncryptTab")
        
        from dashboard.logs_tab import LogsTab
        print("  ✓ LogsTab")
        
        from dashboard.report_tab import ReportTab
        print("  ✓ ReportTab")
        
        from dashboard.settings_tab import SettingsTab
        print("  ✓ SettingsTab")
        
        from dashboard.pdf_generator import PDFReportGenerator
        print("  ✓ PDFReportGenerator")
        
        return True
    except Exception as e:
        print(f"  ✗ Import failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("=" * 60)
    print("   BLUE TEAM SYSTEM - DAY 3 INTEGRATION TEST")
    print("=" * 60)
    
    all_passed = True
    
    if not test_imports():
        all_passed = False
    
    if not test_database_enhancements():
        all_passed = False
    
    if not test_pdf_generation():
        all_passed = False
    
    print("\n" + "=" * 60)
    if all_passed:
        print("   ✅ ALL DAY 3 TESTS PASSED!")
        print("\n   MVP is ready for presentation!")
    else:
        print("   ❌ SOME TESTS FAILED")
    print("=" * 60 + "\n")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())