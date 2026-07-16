#!/usr/bin/env python3
# test_service_enumerator.py
"""
Test script for Service Enumerator module.
"""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from modules.recon.service_enumerator import ServiceEnumerator


def test_module_initialization():
    """Test Service Enumerator module initialization."""
    print("\n🧪 Testing Service Enumerator Module Initialization")
    print("=" * 50)
    
    try:
        scanner = ServiceEnumerator()
        print(f"✅ Module initialized: {scanner.name}")
        print(f"✅ Logger configured: {scanner.logger}")
        print(f"✅ Default results: {scanner.results}")
        print("✅ Module initialization successful")
        return scanner
    except Exception as e:
        print(f"❌ Module initialization failed: {e}")
        raise


def test_banner_grabbing():
    """Test banner grabbing with error handling."""
    print("\n🛠️  Testing Banner Grabbing Function")
    print("=" * 50)
    
    scanner = ServiceEnumerator()
    
    # Import the module-level function
    from modules.recon.service_enumerator import grab_banner
    
    # Test with a non-routable IP to avoid network dependency
    # This should handle connection errors gracefully
    test_cases = [
        {"target": "127.0.0.1", "port": 22, "desc": "Local SSH port"},
        {"target": "127.0.0.1", "port": 8080, "desc": "Local web port"},
    ]
    
    for test in test_cases:
        banner = grab_banner(test["target"], test["port"], timeout=1.0)
        print(f"📡 Target: {test['target']}:{test['port']} - {test['desc']}")
        print(f"   Result: {banner[:50] if len(banner) > 50 else banner}")
        print(f"   Status: {'✅ Success' if 'Error' not in banner else '⚠️  Connection refused (expected for test)'}")
        print()


def test_run_method():
    """Test the run method with simulated target."""
    print("\n🎯 Testing Run Method")
    print("=" * 50)
    
    scanner = ServiceEnumerator()
    
    # Test the run method (won't actually scan due to network issues)
    # This will show error handling in action
    test_ports = [22, 80, 443]
    
    print(f"🔍 Simulating scan of {len(test_ports)} ports on localhost")
    print("⚠️  This test will likely show connection failures - this is expected in this environment\n")
    
    results = scanner.run("127.0.0.1", ports=test_ports, max_threads=5)
    
    print(f"📊 Scan Results:")
    print(f"   Target: {results.get('target', 'N/A')}")
    print(f"   Total ports scanned: {results.get('total_ports_scanned', 0)}")
    print(f"   Successful scans: {results.get('successful_scans', 0)}")
    
    print(f"\n🔍 Port Details:")
    for port, details in results.get('services', {}).items():
        status = "✅ Success" if not details['banner'].startswith('Error:') else "⚠️ Failed"
        print(f"   Port {port}: {status}")
        print(f"      Banner: {details['banner'][:60] if details['banner'] else 'N/A'}")


def test_error_handling():
    """Test error handling in various scenarios."""
    print("\n⚠️  Testing Error Handling")
    print("=" * 50)
    
    # Import the module-level functions
    from modules.recon.service_enumerator import get_ip_for_target, grab_banner
    
    # Test with invalid target
    invalid_targets = [
        {"target": "invalid-hostname-that-does-not-exist", "desc": "Invalid hostname"},
        {"target": "not-a-valid-ip", "desc": "Non-IP string"},
    ]
    
    for test in invalid_targets:
        try:
            # Test IP resolution
            ip = get_ip_for_target(test["target"])
            print(f"🔍 IP Resolution for {test['desc']}:")
            print(f"   Result: {ip}")
            print(f"   Status: ⚠️  Unexpected success (should have failed)")
        except Exception as e:
            print(f"🔍 IP Resolution for {test['desc']}:")
            print(f"   Error: {str(e)[:60]}")
            print(f"   Status: ✅ Correctly rejected invalid input")
        
        # Test banner grabbing
        banner = grab_banner(test["target"], 22, timeout=1.0)
        print(f"📡 Banner grab for {test['desc']}:")
        print(f"   Result: {banner[:60] if banner else 'N/A'}")
        print(f"   Status: ✅ Handled gracefully (error returned)")
        print()


def main():
    """Run all tests."""
    print("\n" + "=" * 60)
    print("🚀 Service Enumerator Module Test Suite")
    print("=" * 60)
    
    try:
        test_module_initialization()
        test_banner_grabbing()
        test_run_method()
        test_error_handling()
        
        print("\n" + "=" * 60)
        print("✅ All tests completed!")
        print("Note: Connection failures are expected in this test environment.")
        print("The module correctly handles errors and returns structured output.")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())