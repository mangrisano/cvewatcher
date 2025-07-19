import requests

BASE_URL = "http://localhost:8000"

def test_asset_management():
    print("🔍 Testing Asset Management Features")

    login_data = {"email": "m.angrisano@namirial.com", "password": "newpassword123"}

    login_response = requests.post(f"{BASE_URL}/login", json=login_data)
    if login_response.status_code != 200:
        print(f"❌ Login failed: {login_response.text}")
        return

    token = login_response.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    print("✅ Login successful")

    print("\n📦 Test 1: Register Apache HTTP Server")
    asset_data = {
        "name": "Apache HTTP Server",
        "version": "2.4.41",
        "cpe": "cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
        "description": "Web server running on production environment",
    }

    response = requests.post(f"{BASE_URL}/assets", json=asset_data, headers=headers)
    if response.status_code == 201:
        asset = response.json()
        asset_id = asset["id"]
        print(f"✅ Asset registered successfully: ID {asset_id}")
        print(f"   Name: {asset['name']}")
        print(f"   Version: {asset['version']}")
        print(f"   CPE: {asset['cpe']}")
    else:
        print(f"❌ Asset registration failed: {response.text}")
        return

    print("\n📋 Test 2: Get my assets")
    response = requests.get(f"{BASE_URL}/assets", headers=headers)
    if response.status_code == 200:
        assets = response.json()
        print(f"✅ Retrieved {len(assets)} assets")
        for asset in assets:
            print(f"   - {asset['name']} v{asset.get('version', 'N/A')}")
    else:
        print(f"❌ Failed to get assets: {response.text}")
        return

    print(f"\n🚨 Test 3: Get vulnerabilities for asset {asset_id}")
    response = requests.get(
        f"{BASE_URL}/assets/{asset_id}/vulnerabilities", headers=headers
    )
    if response.status_code == 200:
        result = response.json()
        vulns = result["vulnerabilities"]
        print(f"✅ Found {len(vulns)} vulnerabilities")
        print(f"   Search queries used: {result.get('search_queries_used', [])}")

        for i, vuln in enumerate(vulns[:3]):
            print(
                f"   {i + 1}. {vuln['cve_id']} - {vuln['severity']} ({vuln.get('score', 'N/A')})"
            )
            print(f"      {vuln['summary'][:100]}...")
    else:
        print(f"❌ Failed to get vulnerabilities: {response.text}")

    print("\n📦 Test 4: Register WordPress")
    asset_data = {
        "name": "WordPress",
        "version": "6.0.1",
        "description": "Content management system",
    }

    response = requests.post(f"{BASE_URL}/assets", json=asset_data, headers=headers)
    if response.status_code == 201:
        asset = response.json()
        wordpress_id = asset["id"]
        print(f"✅ WordPress registered: ID {wordpress_id}")

        print("\n🚨 Test 5: Get vulnerabilities for WordPress")
        response = requests.get(
            f"{BASE_URL}/assets/{wordpress_id}/vulnerabilities", headers=headers
        )
        if response.status_code == 200:
            result = response.json()
            vulns = result["vulnerabilities"]
            print(f"✅ Found {len(vulns)} WordPress vulnerabilities")

            for i, vuln in enumerate(vulns[:2]):
                print(f"   {i + 1}. {vuln['cve_id']} - {vuln['severity']}")
        else:
            print(f"❌ Failed to get WordPress vulnerabilities: {response.text}")
    else:
        print(f"❌ WordPress registration failed: {response.text}")
        print("⚠️ Skipping WordPress vulnerability test")

    print("\n🎉 Asset management tests completed!")

if __name__ == "__main__":
    try:
        test_asset_management()
    except requests.exceptions.ConnectionError:
        print(
            "❌ Could not connect to the server. Make sure it's running on http://localhost:8000"
        )
    except Exception as e:
        print(f"❌ Test error: {e}")
