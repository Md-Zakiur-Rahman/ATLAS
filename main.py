#!/usr/bin/env python3
"""
Blue Team Threat Detection System
Entry point for the application

Usage:
    python main.py
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dashboard.app import main

if __name__ == "__main__":
    main()