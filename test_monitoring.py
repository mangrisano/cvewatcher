import requests

BASE_URL = "http://localhost:8000"

BASE_URL = "http://localhost:8000"

def test_cve_monitoring():
    print("🔍 Testing CVE Monitoring System")
    print("=" * 50)

    login_data = {"email": "m.angrisano@namirial.com", "password": "testpass123"}

    login_response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
    if login_response.status_code != 200:
        print(f"❌ Login failed: {login_response.text}")
        return

    token = login_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    print("✅ Login successful")

    print("\n📋 Test 1: Get registered assets")
    response = requests.get(f"{BASE_URL}/assets", headers=headers)
    if response.status_code == 200:
        assets = response.json()
        print(f"✅ Found {len(assets)} registered assets:")
        for asset in assets:
            print(
                f"   - ID: {asset['id']}, Name: {asset['name']}, Version: {asset.get('version', 'N/A')}"
            )

        if not assets:
            print("⚠️  No assets found. Please register an asset first.")
            return

        test_asset_id = assets[0]["id"]
        asset_name = assets[0]["name"]

    else:
        print(f"❌ Failed to get assets: {response.text}")
        return

    print(f"\n🔍 Test 2: Monitor asset '{asset_name}' (ID: {test_asset_id})")
    response = requests.get(
        f"{BASE_URL}/assets/{test_asset_id}/monitor", headers=headers
    )
    if response.status_code == 200:
        result = response.json()
        monitoring_result = result.get("monitoring_result", {})

        print("✅ Asset monitoring completed:")
        print(
            f"   Asset: {monitoring_result.get('asset_name')} v{monitoring_result.get('asset_version')}"
        )
        print(
            f"   Total Vulnerabilities: {monitoring_result.get('total_vulnerabilities', 0)}"
        )
        print(
            f"   New Vulnerabilities: {len(monitoring_result.get('new_vulnerabilities', []))}"
        )
        print(f"   Status: {monitoring_result.get('status')}")

        new_vulns = monitoring_result.get("new_vulnerabilities", [])
        if new_vulns:
            print("   🚨 New vulnerabilities found:")
            for vuln in new_vulns[:3]:  
                print(
                    f"      - {vuln.get('cve_id')}: {vuln.get('severity')} (Score: {vuln.get('score', 'N/A')})"
                )
        else:
            print("   ℹ️  No new vulnerabilities since last check")
    else:
        print(f"❌ Failed to monitor asset: {response.text}")

    print("\n📊 Test 3: Generate monitoring report (last 30 days)")
    response = requests.get(f"{BASE_URL}/monitoring/report?days=30", headers=headers)
    if response.status_code == 200:
        report = response.json()

        print("✅ Monitoring report generated:")
        print(f"   Report period: {report.get('report_period_days', 0)} days")
        print(f"   Total assets monitored: {report.get('total_assets', 0)}")

        summary = report.get("vulnerability_summary", {})
        print("   Recent vulnerabilities:")
        print(f"     - Total: {summary.get('total_recent', 0)}")
        print(f"     - Critical: {summary.get('critical', 0)}")
        print(f"     - High: {summary.get('high', 0)}")
        print(f"     - Medium: {summary.get('medium', 0)}")
        print(f"     - Low: {summary.get('low', 0)}")

        recent_vulns = report.get("recent_vulnerabilities", [])
        if recent_vulns:
            print("   🔥 Most recent vulnerabilities:")
            for vuln in recent_vulns[:5]:
                print(f"      - {vuln.get('cve_id')}: {vuln.get('severity')}")
    else:
        print(f"❌ Failed to generate report: {response.text}")

    print("\n🔍 Test 4: Scan all user assets")
    response = requests.post(f"{BASE_URL}/monitoring/scan-all", headers=headers)
    if response.status_code == 200:
        scan_result = response.json()

        print("✅ Asset scan completed:")
        print(f"   Timestamp: {scan_result.get('timestamp')}")
        print(f"   Assets scanned: {scan_result.get('total_assets_scanned', 0)}")

        asset_results = scan_result.get("asset_results", [])
        for result in asset_results:
            status = result.get("status")
            if status == "success":
                print(
                    f"   ✅ {result.get('asset_name')}: {result.get('total_vulnerabilities', 0)} total, {len(result.get('new_vulnerabilities', []))} new"
                )
            else:
                print(
                    f"   ❌ {result.get('asset_name')}: Error - {result.get('error')}"
                )
    else:
        print(f"❌ Failed to scan assets: {response.text}")

    print("\n" + "=" * 50)
    print("🎉 CVE Monitoring system tests completed!")
    print("\n💡 Key Features Available:")
    print("   • Monitor individual assets: GET /assets/{id}/monitor")
    print("   • Generate monitoring reports: GET /monitoring/report?days=X")
    print("   • Scan all user assets: POST /monitoring/scan-all")
    print("   • Regular vulnerability detection for registered assets")
    print("   • Track new vs existing vulnerabilities")
    print("   • Severity-based vulnerability categorization")

if __name__ == "__main__":
    try:
        test_cve_monitoring()
    except requests.exceptions.ConnectionError:
        print(
            "❌ Could not connect to the server. Make sure it's running on http://localhost:8000"
        )
    except Exception as e:
        print(f"❌ Test error: {e}")
