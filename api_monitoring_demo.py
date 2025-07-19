import requests

class CVEMonitorAPI:

    def __init__(self, base_url="http://localhost:8000"):
        self.base_url = base_url
        self.token = None
        self.headers = {}

    def login(self, email: str, password: str) -> bool:
        try:
            response = requests.post(
                f"{self.base_url}/login", json={"email": email, "password": password}
            )

            if response.status_code == 200:
                self.token = response.json()["token"]
                self.headers = {"Authorization": f"Bearer {self.token}"}
                print(f"✅ Successfully logged in as {email}")
                return True
            else:
                print(f"❌ Login failed: {response.text}")
                return False

        except Exception as e:
            print(f"❌ Login error: {e}")
            return False

    def register_asset(
        self, name: str, version: str, cpe: str = "", description: str = ""
    ) -> dict:
        try:
            data = {
                "name": name,
                "version": version,
                "cpe": cpe,
                "description": description,
            }

            response = requests.post(
                f"{self.base_url}/assets", json=data, headers=self.headers
            )

            if response.status_code == 201:
                asset = response.json()
                print(f"✅ Asset registered: {name} v{version} (ID: {asset['id']})")
                return asset
            else:
                print(f"❌ Asset registration failed: {response.text}")
                return {}

        except Exception as e:
            print(f"❌ Error registering asset: {e}")
            return {}

    def get_assets(self) -> list:
        try:
            response = requests.get(f"{self.base_url}/assets", headers=self.headers)

            if response.status_code == 200:
                assets = response.json()
                print(f"✅ Retrieved {len(assets)} assets")
                return assets
            else:
                print(f"❌ Failed to get assets: {response.text}")
                return []

        except Exception as e:
            print(f"❌ Error getting assets: {e}")
            return []

    def get_asset_vulnerabilities(self, asset_id: int) -> dict:
        try:
            response = requests.get(
                f"{self.base_url}/assets/{asset_id}/vulnerabilities",
                headers=self.headers,
            )

            if response.status_code == 200:
                result = response.json()
                vulns = result.get("vulnerabilities", [])
                print(f"✅ Found {len(vulns)} vulnerabilities for asset {asset_id}")
                return result
            else:
                print(f"❌ Failed to get vulnerabilities: {response.text}")
                return {}

        except Exception as e:
            print(f"❌ Error getting vulnerabilities: {e}")
            return {}

    def monitor_asset(self, asset_id: int) -> dict:
        try:
            response = requests.get(
                f"{self.base_url}/assets/{asset_id}/monitor", headers=self.headers
            )

            if response.status_code == 200:
                result = response.json()
                monitoring_result = result.get("monitoring_result", {})
                new_vulns = len(monitoring_result.get("new_vulnerabilities", []))
                print(
                    f"✅ Asset monitoring completed. Found {new_vulns} new vulnerabilities"
                )
                return result
            else:
                print(f"❌ Asset monitoring failed: {response.text}")
                return {}

        except Exception as e:
            print(f"❌ Error monitoring asset: {e}")
            return {}

    def get_monitoring_report(self, days: int = 7) -> dict:
        try:
            response = requests.get(
                f"{self.base_url}/monitoring/report?days={days}", headers=self.headers
            )

            if response.status_code == 200:
                report = response.json()
                total_assets = report.get("total_assets", 0)
                recent_vulns = len(report.get("recent_vulnerabilities", []))
                print(
                    f"✅ Report generated: {total_assets} assets, {recent_vulns} recent vulnerabilities"
                )
                return report
            else:
                print(f"❌ Failed to generate report: {response.text}")
                return {}

        except Exception as e:
            print(f"❌ Error generating report: {e}")
            return {}

    def scan_all_assets(self) -> dict:
        try:
            response = requests.post(
                f"{self.base_url}/monitoring/scan-all", headers=self.headers
            )

            if response.status_code == 200:
                result = response.json()
                assets_scanned = result.get("total_assets_scanned", 0)
                print(f"✅ Scanned {assets_scanned} assets for new vulnerabilities")
                return result
            else:
                print(f"❌ Asset scanning failed: {response.text}")
                return {}

        except Exception as e:
            print(f"❌ Error scanning assets: {e}")
            return {}

    def delete_asset(self, asset_id: int) -> bool:
        try:
            response = requests.delete(
                f"{self.base_url}/assets/{asset_id}", headers=self.headers
            )

            if response.status_code == 200:
                print(f"✅ Asset {asset_id} deleted successfully")
                return True
            else:
                print(f"❌ Failed to delete asset: {response.text}")
                return False

        except Exception as e:
            print(f"❌ Error deleting asset: {e}")
            return False

def demo_monitoring_workflow():
    print("🚀 CVE Monitor API Demo")
    print("=" * 50)

    api = CVEMonitorAPI()

    if not api.login("m.angrisano@namirial.com", "newpassword123"):
        return

    print("\n📦 Step 1: Register some assets")

    api.register_asset(
        name="Apache HTTP Server",
        version="2.4.41",
        cpe="cpe:2.3:a:apache:http_server:2.4.41:*:*:*:*:*:*:*",
        description="Production web server",
    )

    api.register_asset(
        name="nginx", version="1.18.0", description="Reverse proxy server"
    )

    print("\n📋 Step 2: List all assets")
    assets = api.get_assets()
    for asset in assets:
        print(f"  - {asset['name']} v{asset['version']} (ID: {asset['id']})")

    if assets:
        asset_id = assets[0]["id"]

        print(f"\n🔍 Step 3: Get vulnerabilities for asset {asset_id}")
        vulnerabilities = api.get_asset_vulnerabilities(asset_id)

        vulns = vulnerabilities.get("vulnerabilities", [])
        if vulns:
            print("🚨 Top 3 vulnerabilities:")
            for i, vuln in enumerate(vulns[:3], 1):
                print(
                    f"  {i}. {vuln['cve_id']} - {vuln['severity']} (Score: {vuln.get('score', 'N/A')})"
                )
                print(f"     {vuln['summary'][:100]}...")

        print(f"\n🔄 Step 4: Monitor asset {asset_id} for new CVEs")
        monitoring_result = api.monitor_asset(asset_id)

        if monitoring_result:
            result = monitoring_result.get("monitoring_result", {})
            new_vulns = result.get("new_vulnerabilities", [])

            if new_vulns:
                print(f"🆕 Found {len(new_vulns)} new vulnerabilities:")
                for vuln in new_vulns[:3]:
                    print(f"  - {vuln['cve_id']}: {vuln['severity']}")
            else:
                print("✅ No new vulnerabilities found since last check")

    print("\n📊 Step 5: Generate monitoring report (last 30 days)")
    report = api.get_monitoring_report(days=30)

    if report:
        summary = report.get("vulnerability_summary", {})
        print("Vulnerability Summary:")
        print(f"  🔴 Critical: {summary.get('critical', 0)}")
        print(f"  🟠 High: {summary.get('high', 0)}")
        print(f"  🟡 Medium: {summary.get('medium', 0)}")
        print(f"  🟢 Low: {summary.get('low', 0)}")

    print("\n🔍 Step 6: Scan all assets")
    scan_results = api.scan_all_assets()

    if scan_results:
        asset_results = scan_results.get("asset_results", [])
        for result in asset_results:
            if result.get("status") == "success":
                asset_name = result.get("asset_name")
                new_count = len(result.get("new_vulnerabilities", []))
                total_count = result.get("total_vulnerabilities", 0)
                print(f"  📦 {asset_name}: {total_count} total, {new_count} new")

    print("\n✅ API Demo completed!")

if __name__ == "__main__":
    try:
        demo_monitoring_workflow()
    except KeyboardInterrupt:
        print("\n\n⏹️ Demo interrupted by user")
    except requests.exceptions.ConnectionError:
        print(
            "❌ Could not connect to CVE Monitor API. Make sure the server is running on http://localhost:8000"
        )
    except Exception as e:
        print(f"❌ Demo error: {e}")
