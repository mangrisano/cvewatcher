window.BENCHMARK_DATA = {
  "lastUpdate": 1785533420976,
  "repoUrl": "https://github.com/mangrisano/cvewatcher",
  "entries": {
    "cvewatcher benchmarks": [
      {
        "commit": {
          "author": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "committer": {
            "email": "michele.angrisano@gmail.com",
            "name": "Michele Angrisano",
            "username": "mangrisano"
          },
          "distinct": true,
          "id": "6e207ec8cea65e7912bf3c5fb7416d426f47163d",
          "message": "ci: add performance benchmark workflow and badge",
          "timestamp": "2026-07-31T23:29:47+02:00",
          "tree_id": "03e75790e4c0017e5d63520cff79be38d0372f01",
          "url": "https://github.com/mangrisano/cvewatcher/commit/6e207ec8cea65e7912bf3c5fb7416d426f47163d"
        },
        "date": 1785533420434,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 84743.12586311573,
            "unit": "iter/sec",
            "range": "stddev: 0.0000037329806822994703",
            "extra": "mean: 11.800367166244076 usec\nrounds: 20217"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 50577.7974000673,
            "unit": "iter/sec",
            "range": "stddev: 0.000002981595130491001",
            "extra": "mean: 19.771521327630403 usec\nrounds: 15004"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18916.290048006293,
            "unit": "iter/sec",
            "range": "stddev: 0.000002589459615961606",
            "extra": "mean: 52.86448862129794 usec\nrounds: 11293"
          }
        ]
      }
    ]
  }
}