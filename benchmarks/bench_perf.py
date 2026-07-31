"""Performance benchmarks for cvewatcher's pure CVE-matching hot path.

Run in CI by the Performance workflow via pytest-benchmark. The ``bench_*``
filename keeps them out of default test collection. They exercise the
network-free matching engine (CPE-to-name matching and version-range checks)
that runs for every asset against every candidate CVE product.
"""

from app.services.cve_monitoring import CVEMonitoringService as Svc

_CPES = [
    "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*",
    "cpe:2.3:a:nginx:nginx:1.20.1:*:*:*:*:*:*:*",
    "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:tomcat:9.0.54:*:*:*:*:*:*:*",
    "cpe:2.3:o:linux:linux_kernel:5.15:*:*:*:*:*:*:*",
    "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
]
_VARIANTS = Svc._name_variants("apache http server")
_VERSIONS = ["0.9", "1.5.0", "2.0.0", "2.4.51", "3.1.4"]
_PRODUCT = {"version_start": "2.4.0", "version_end": "2.4.52"}


def test_cpe_matches_name(benchmark):
    benchmark(lambda: [Svc._cpe_matches_name(cpe, _VARIANTS) for cpe in _CPES])


def test_version_affected(benchmark):
    benchmark(lambda: [Svc._version_affected(v, _PRODUCT) for v in _VERSIONS])


def test_match_pipeline(benchmark):
    def run():
        hits = 0
        for cpe in _CPES:
            if Svc._cpe_matches_name(cpe, _VARIANTS):
                hits += sum(Svc._version_affected(v, _PRODUCT) for v in _VERSIONS)
        return hits

    benchmark(run)
