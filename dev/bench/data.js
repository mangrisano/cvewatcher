window.BENCHMARK_DATA = {
  "lastUpdate": 1785924204720,
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
      },
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
          "id": "5bf663a85c67a9cff2d3c0019a883a6ac85833b7",
          "message": "ci: pin ruff lint rule set to keep CI stable across ruff versions",
          "timestamp": "2026-07-31T23:36:27+02:00",
          "tree_id": "d9e3c119464b4628708ea50ddaffba35a870e5dc",
          "url": "https://github.com/mangrisano/cvewatcher/commit/5bf663a85c67a9cff2d3c0019a883a6ac85833b7"
        },
        "date": 1785533823746,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 98013.4271369013,
            "unit": "iter/sec",
            "range": "stddev: 0.0000010353722597440356",
            "extra": "mean: 10.202683746618096 usec\nrounds: 20648"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 53954.44028452483,
            "unit": "iter/sec",
            "range": "stddev: 0.000005593946755537745",
            "extra": "mean: 18.534155756719418 usec\nrounds: 16789"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 21904.15090898469,
            "unit": "iter/sec",
            "range": "stddev: 0.000002720462407976836",
            "extra": "mean: 45.653447337683275 usec\nrounds: 12865"
          }
        ]
      },
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
          "id": "345b46bf34ee0c5f5d059ae3fa42ec7a7e6a3c98",
          "message": "docs: redesign logo with a distinct cyan bug identity",
          "timestamp": "2026-08-01T00:07:16+02:00",
          "tree_id": "ff3f09aa57ce4ed176386a4b6bd5a2e4e3724c7b",
          "url": "https://github.com/mangrisano/cvewatcher/commit/345b46bf34ee0c5f5d059ae3fa42ec7a7e6a3c98"
        },
        "date": 1785535667352,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 80802.19273559508,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012240584852558532",
            "extra": "mean: 12.375901768807802 usec\nrounds: 22162"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 49190.859956469176,
            "unit": "iter/sec",
            "range": "stddev: 0.000002681411788968925",
            "extra": "mean: 20.328979832532657 usec\nrounds: 16363"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 17977.08442020433,
            "unit": "iter/sec",
            "range": "stddev: 0.0000035081473550434925",
            "extra": "mean: 55.62637281027097 usec\nrounds: 10732"
          }
        ]
      },
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
          "id": "f40f32140e655239c3d4f75fb7ff4fdacbec2d85",
          "message": "chore(release): 0.7.0",
          "timestamp": "2026-08-05T11:57:04+02:00",
          "tree_id": "743fea7a6c9b8f2ec0807c5d856efbd64f97cbd7",
          "url": "https://github.com/mangrisano/cvewatcher/commit/f40f32140e655239c3d4f75fb7ff4fdacbec2d85"
        },
        "date": 1785923866632,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 89618.31564507716,
            "unit": "iter/sec",
            "range": "stddev: 0.0000011998340402570694",
            "extra": "mean: 11.158433326959445 usec\nrounds: 20938"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48519.30550236368,
            "unit": "iter/sec",
            "range": "stddev: 0.000003161200478756015",
            "extra": "mean: 20.610352717255687 usec\nrounds: 15236"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18600.14360276748,
            "unit": "iter/sec",
            "range": "stddev: 0.000002812670390350065",
            "extra": "mean: 53.76302577853281 usec\nrounds: 11560"
          }
        ]
      },
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
          "id": "08ee64f8b6281dea22d0f1286e2daa7d7b9770ee",
          "message": "ci: install types-sqlalchemy so pyright resolves ORM attribute types",
          "timestamp": "2026-08-05T12:02:46+02:00",
          "tree_id": "02e50532d1fa9ecabb496d456011942c8e3f3b52",
          "url": "https://github.com/mangrisano/cvewatcher/commit/08ee64f8b6281dea22d0f1286e2daa7d7b9770ee"
        },
        "date": 1785924203894,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 84655.94716043667,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012100476008201214",
            "extra": "mean: 11.812519185507888 usec\nrounds: 22491"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 46743.034883891305,
            "unit": "iter/sec",
            "range": "stddev: 0.0000032799684752610768",
            "extra": "mean: 21.393561682162453 usec\nrounds: 16431"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 17878.939109830866,
            "unit": "iter/sec",
            "range": "stddev: 0.000004318065656408562",
            "extra": "mean: 55.9317302809171 usec\nrounds: 11182"
          }
        ]
      }
    ]
  }
}