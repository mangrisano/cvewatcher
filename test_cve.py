#!/usr/bin/env python3
"""
Test script to verify CVE integration
"""

import json
import urllib.request
import urllib.parse

BASE_URL = "http://127.0.0.1:8000"


def test_cve_integration():
    print("🧪 Test CVE Integration")
    print("=" * 50)

    print("1. Testing health endpoint...")
    try:
        response = urllib.request.urlopen(f"{BASE_URL}/health")
        result = json.loads(response.read().decode())
        print(f"   ✅ Health: {result}")
    except Exception as e:
        print(f"   ❌ Health failed: {e}")
        return

    print("\n2. Registering test user...")
    try:
        data = json.dumps(
            {
                "username": "cvetest2",
                "email": "cvetest2@example.com",
                "password": "TestPass123!",
            }
        ).encode()

        req = urllib.request.Request(f"{BASE_URL}/auth/register", data=data)
        req.add_header("Content-Type", "application/json")

        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())
        print(f"   ✅ Registration: {result}")
    except Exception as e:
        print(f"   ⚠️  Registration (may already exist): {e}")

    print("\n3. Logging in...")
    try:
        data = json.dumps(
            {"email": "cvetest2@example.com", "password": "TestPass123!"}
        ).encode()

        req = urllib.request.Request(f"{BASE_URL}/auth/login", data=data)
        req.add_header("Content-Type", "application/json")

        response = urllib.request.urlopen(req)
        result = json.loads(response.read().decode())
        token = result["access_token"]
        print(f"   ✅ Login successful, token: {token[:30]}...")

        print("\n4. Testing CVE search...")
        search_req = urllib.request.Request(f"{BASE_URL}/cves/search?product=apache")
        search_req.add_header("Authorization", f"Bearer {token}")

        search_response = urllib.request.urlopen(search_req)
        search_result = json.loads(search_response.read().decode())

        print("   ✅ CVE Search successful:")
        print(f"      - Product: {search_result['product']}")
        print(f"      - CVE Count: {search_result['cve_count']}")

        if search_result["cves"]:
            first_cve = search_result["cves"][0]
            print(f"      - First CVE: {first_cve['cve_id']}")
            print(f"        Severity: {first_cve['severity']}")
            print(f"        Score: {first_cve['score']}")

        print("\n5. Testing recent CVE fetch...")
        fetch_req = urllib.request.Request(
            f"{BASE_URL}/cves/fetch-recent?days=1", data=b""
        )
        fetch_req.add_header("Authorization", f"Bearer {token}")
        fetch_req.get_method = lambda: "POST"

        fetch_response = urllib.request.urlopen(fetch_req)
        fetch_result = json.loads(fetch_response.read().decode())
        print(f"   ✅ Recent CVE fetch: {fetch_result}")

        print("\n🎉 All tests completed successfully!")

    except Exception as e:
        print(f"   ❌ Login/CVE test failed: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    test_cve_integration()
