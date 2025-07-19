#!/usr/bin/env python3
"""
Test delle vulnerabilities endpoint
"""

import urllib.request
import urllib.error
import json


def test_vulnerabilities():
    try:
        # Login
        login_data = json.dumps(
            {"email": "m.angrisano@namirial.com", "password": "password123"}
        ).encode("utf-8")

        login_req = urllib.request.Request(
            "http://localhost:8000/auth/login",
            data=login_data,
            headers={"Content-Type": "application/json"},
        )

        print("🔐 Testing vulnerabilities endpoint fix...")
        with urllib.request.urlopen(login_req) as response:
            login_result = json.loads(response.read().decode())
            token = login_result["access_token"]
            print("✅ Login successful")

        # Test vulnerabilities endpoint
        vuln_req = urllib.request.Request(
            "http://localhost:8000/cves/vulnerabilities",
            headers={"Authorization": f"Bearer {token}"},
        )

        with urllib.request.urlopen(vuln_req) as response:
            vuln_result = json.loads(response.read().decode())
            print(f"✅ Vulnerabilities endpoint working! Response: {vuln_result}")

        # Test recent endpoint
        recent_req = urllib.request.Request(
            "http://localhost:8000/cves/recent",
            headers={"Authorization": f"Bearer {token}"},
        )

        with urllib.request.urlopen(recent_req) as response:
            recent_result = json.loads(response.read().decode())
            print(f"✅ Recent CVEs endpoint working! Found {len(recent_result)} CVEs")

        print("\n🎉 All endpoints are now working correctly!")
        return True

    except urllib.error.HTTPError as e:
        print(f"❌ HTTP Error: {e.code} - {e.reason}")
        try:
            error_body = e.read().decode()
            print(f"   Error details: {error_body}")
        except:
            pass
        return False
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


if __name__ == "__main__":
    test_vulnerabilities()
