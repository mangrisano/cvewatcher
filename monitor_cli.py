import requests
import sys
from datetime import datetime

BASE_URL = "http://localhost:8000"

class CVEMonitorCLI:
    def __init__(self):
        self.token = None
        self.headers = None

    def login(self):
        print("🔐 Logging in...")
        login_data = {"email": "m.angrisano@namirial.com", "password": "testpass123"}

        try:
            response = requests.post(f"{BASE_URL}/auth/login", json=login_data)
            if response.status_code == 200:
                self.token = response.json()["access_token"]
                self.headers = {"Authorization": f"Bearer {self.token}"}
                print("✅ Login successful")
                return True
            else:
                print(f"❌ Login failed: {response.text}")
                return False
        except Exception as e:
            print(f"❌ Connection error: {e}")
            return False

    def list_assets(self):
        print("\n📋 Your Registered Assets:")
        print("-" * 40)

        try:
            response = requests.get(f"{BASE_URL}/assets", headers=self.headers)
            if response.status_code == 200:
                assets = response.json()
                if not assets:
                    print("No assets registered yet.")
                    return []

                for asset in assets:
                    print(
                        f"ID: {asset['id']} | {asset['name']} v{asset.get('version', 'N/A')}"
                    )
                    if asset.get("description"):
                        print(f"    Description: {asset['description']}")
                    print()
                return assets
            else:
                print(f"❌ Failed to get assets: {response.text}")
                return []
        except Exception as e:
            print(f"❌ Error: {e}")
            return []

    def monitor_asset(self, asset_id):
        print(f"\n🔍 Monitoring Asset ID: {asset_id}")
        print("-" * 40)

        try:
            response = requests.get(
                f"{BASE_URL}/assets/{asset_id}/vulnerabilities", headers=self.headers
            )
            if response.status_code == 200:
                result = response.json()
                asset_info = result.get("asset", {})
                vulnerabilities = result.get("vulnerabilities", [])

                print(
                    f"Asset: {asset_info.get('name')} v{asset_info.get('version', 'N/A')}"
                )
                print(f"Total Vulnerabilities Found: {len(vulnerabilities)}")

                if vulnerabilities:
                    
                    severity_counts = {}
                    for vuln in vulnerabilities:
                        severity = vuln.get("severity", "UNKNOWN")
                        severity_counts[severity] = severity_counts.get(severity, 0) + 1

                    print("\nSeverity Breakdown:")
                    for severity, count in sorted(severity_counts.items()):
                        print(f"  {severity}: {count}")

                    print("\n🚨 Most Critical Vulnerabilities:")
                    
                    critical_vulns = [
                        v
                        for v in vulnerabilities
                        if v.get("severity") in ["CRITICAL", "HIGH"]
                    ]
                    critical_vulns.sort(key=lambda x: x.get("score", 0), reverse=True)

                    for vuln in critical_vulns[:5]:  
                        score = vuln.get("score", "N/A")
                        date = (
                            vuln.get("publish_date", "N/A")[:10]
                            if vuln.get("publish_date")
                            else "N/A"
                        )
                        print(
                            f"  • {vuln.get('cve_id')} - {vuln.get('severity')} (Score: {score}) [{date}]"
                        )
                        print(f"    {vuln.get('summary', '')[:100]}...")
                        print()
                else:
                    print("✅ No vulnerabilities found!")

            else:
                print(f"❌ Failed to monitor asset: {response.text}")

        except Exception as e:
            print(f"❌ Error: {e}")

    def generate_report(self, days=7):
        print(f"\n📊 Monitoring Report (Last {days} days)")
        print("-" * 50)

        try:
            response = requests.get(
                f"{BASE_URL}/monitoring/report?days={days}", headers=self.headers
            )
            if response.status_code == 200:
                report = response.json()

                print(
                    f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                )
                print(f"Assets Monitored: {report.get('total_assets', 0)}")

                summary = report.get("vulnerability_summary", {})
                print("\nVulnerability Summary:")
                print(f"  Total Recent: {summary.get('total_recent', 0)}")
                print(f"  🔴 Critical: {summary.get('critical', 0)}")
                print(f"  🟠 High: {summary.get('high', 0)}")
                print(f"  🟡 Medium: {summary.get('medium', 0)}")
                print(f"  🟢 Low: {summary.get('low', 0)}")

                recent_vulns = report.get("recent_vulnerabilities", [])
                if recent_vulns:
                    print("\n🔥 Latest Vulnerabilities:")
                    for vuln in recent_vulns[:10]:
                        print(f"  • {vuln.get('cve_id')} - {vuln.get('severity')}")

            else:
                print(f"❌ Failed to generate report: {response.text}")

        except Exception as e:
            print(f"❌ Error: {e}")

    def scan_all(self):
        print("\n🔍 Scanning All Assets...")
        print("-" * 40)

        try:
            response = requests.post(
                f"{BASE_URL}/monitoring/scan-all", headers=self.headers
            )
            if response.status_code == 200:
                result = response.json()

                print(f"Scan completed at: {result.get('timestamp')}")
                print(f"Assets scanned: {result.get('total_assets_scanned', 0)}")

                asset_results = result.get("asset_results", [])
                for asset_result in asset_results:
                    status = asset_result.get("status")
                    if status == "success":
                        name = asset_result.get("asset_name")
                        total = asset_result.get("total_vulnerabilities", 0)
                        new = len(asset_result.get("new_vulnerabilities", []))
                        print(f"  ✅ {name}: {total} total vulnerabilities ({new} new)")
                    else:
                        print(
                            f"  ❌ {asset_result.get('asset_name')}: {asset_result.get('error')}"
                        )

            else:
                print(f"❌ Failed to scan assets: {response.text}")

        except Exception as e:
            print(f"❌ Error: {e}")

def main():
    cli = CVEMonitorCLI()

    if len(sys.argv) < 2:
        print("CVE Monitor CLI")
        print("Usage:")
        print("  python monitor_cli.py list              - List all assets")
        print("  python monitor_cli.py monitor <id>      - Monitor specific asset")
        print(
            "  python monitor_cli.py report [days]     - Generate report (default 7 days)"
        )
        print("  python monitor_cli.py scan              - Scan all assets")
        return

    command = sys.argv[1].lower()

    if not cli.login():
        return

    if command == "list":
        cli.list_assets()

    elif command == "monitor":
        if len(sys.argv) < 3:
            print("❌ Please specify asset ID: python monitor_cli.py monitor <id>")
            return
        try:
            asset_id = int(sys.argv[2])
            cli.monitor_asset(asset_id)
        except ValueError:
            print("❌ Asset ID must be a number")

    elif command == "report":
        days = 7
        if len(sys.argv) >= 3:
            try:
                days = int(sys.argv[2])
            except ValueError:
                print("❌ Days must be a number, using default 7 days")
        cli.generate_report(days)

    elif command == "scan":
        cli.scan_all()

    else:
        print(f"❌ Unknown command: {command}")

if __name__ == "__main__":
    main()
