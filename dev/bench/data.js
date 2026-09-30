window.BENCHMARK_DATA = {
  "lastUpdate": 1790786452102,
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
          "id": "aad4a4e86d664005141aff429c3893606aad7d74",
          "message": "chore(release)!: 1.0.0\n\nBREAKING CHANGE: require Python >= 3.13 (dropped 3.12). Docker images now build on python:3.13-slim and CI runs on 3.13 only.",
          "timestamp": "2026-08-05T12:10:26+02:00",
          "tree_id": "2cf90d4bf7a8058b8db4dfb05051a4fd0777e1f8",
          "url": "https://github.com/mangrisano/cvewatcher/commit/aad4a4e86d664005141aff429c3893606aad7d74"
        },
        "date": 1785924666939,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 79947.77015632081,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012449654135196928",
            "extra": "mean: 12.508166244595856 usec\nrounds: 22118"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47327.132737238186,
            "unit": "iter/sec",
            "range": "stddev: 0.000003017913034316046",
            "extra": "mean: 21.129528500110776 usec\nrounds: 15035"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 17639.98644407621,
            "unit": "iter/sec",
            "range": "stddev: 0.0000034633307767552165",
            "extra": "mean: 56.68938596808366 usec\nrounds: 11203"
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
          "id": "07a12c694f0246af1c708daaa3927233ed614da2",
          "message": "chore(release): 2.0.0",
          "timestamp": "2026-08-05T12:31:59+02:00",
          "tree_id": "b0d128af5a65d98cb8b406e9ab815a4a04a5530f",
          "url": "https://github.com/mangrisano/cvewatcher/commit/07a12c694f0246af1c708daaa3927233ed614da2"
        },
        "date": 1785925951374,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 84670.61657659354,
            "unit": "iter/sec",
            "range": "stddev: 0.000001131574067471115",
            "extra": "mean: 11.810472634215367 usec\nrounds: 22857"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47342.57397068386,
            "unit": "iter/sec",
            "range": "stddev: 0.0000035094322572126534",
            "extra": "mean: 21.12263690223591 usec\nrounds: 11647"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 17844.126532821003,
            "unit": "iter/sec",
            "range": "stddev: 0.0000038853465376137826",
            "extra": "mean: 56.04084896846496 usec\nrounds: 10276"
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
          "id": "9a8b3ac749c09b3ee2d2afcaf7e286645700ebc8",
          "message": "chore(release): 2.1.0",
          "timestamp": "2026-08-05T12:59:17+02:00",
          "tree_id": "44c27d36723d0c58a9147bc4d87721a538baff46",
          "url": "https://github.com/mangrisano/cvewatcher/commit/9a8b3ac749c09b3ee2d2afcaf7e286645700ebc8"
        },
        "date": 1785927616469,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 87181.01901131963,
            "unit": "iter/sec",
            "range": "stddev: 0.0000010898338135020107",
            "extra": "mean: 11.470386688989715 usec\nrounds: 19698"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48260.11993538796,
            "unit": "iter/sec",
            "range": "stddev: 0.000005135772247656466",
            "extra": "mean: 20.72104257798839 usec\nrounds: 12025"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18259.46092523013,
            "unit": "iter/sec",
            "range": "stddev: 0.000003266164251021459",
            "extra": "mean: 54.766129410657655 usec\nrounds: 11166"
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
          "id": "d625e859b6ab5cf87798d901e68c871d85461559",
          "message": "feat(osv): derive severity and score from CVSS vectors\n\nOSV.dev findings previously had no score and often UNKNOWN severity. Parse the CVSS vector from the OSV severity[] array (via the cvss library) into a base score and severity band. When the same CVE appears across sources, the merge now keeps the record carrying severity/score.",
          "timestamp": "2026-08-05T13:36:11+02:00",
          "tree_id": "5fb632319fcad77ad753525d51890a26e4890ac7",
          "url": "https://github.com/mangrisano/cvewatcher/commit/d625e859b6ab5cf87798d901e68c871d85461559"
        },
        "date": 1785929820055,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 114766.34204701554,
            "unit": "iter/sec",
            "range": "stddev: 8.594285327810509e-7",
            "extra": "mean: 8.713356042927087 usec\nrounds: 22663"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 63705.69969422248,
            "unit": "iter/sec",
            "range": "stddev: 0.000024180153258901408",
            "extra": "mean: 15.697182588054847 usec\nrounds: 18539"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 23551.440756996442,
            "unit": "iter/sec",
            "range": "stddev: 0.000004621544906543592",
            "extra": "mean: 42.46024735038468 usec\nrounds: 13398"
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
          "id": "e2010c2c96332ac0096f97c903234a2d71de70d6",
          "message": "feat(dashboard): redesign as a static single-page UI\n\nReplace the inline HTML dashboard with a static single-page app under app/static (sidebar with Overview / Assets / Findings, dark & light themes, user menu). Mount StaticFiles and serve it at /dashboard.\n\nOverview shows the security posture; Assets offers full CRUD with an ecosystem field; Findings is a global table with inline triage, severity/KEV/EPSS badges, filtering and CSV/JSON export.",
          "timestamp": "2026-08-05T14:31:59+02:00",
          "tree_id": "e3fe02e71baf885d8200e10604360ddadb7acccb",
          "url": "https://github.com/mangrisano/cvewatcher/commit/e2010c2c96332ac0096f97c903234a2d71de70d6"
        },
        "date": 1785933154539,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 82915.36205800054,
            "unit": "iter/sec",
            "range": "stddev: 0.0000011772562601219857",
            "extra": "mean: 12.060491266992058 usec\nrounds: 19352"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47751.821765489025,
            "unit": "iter/sec",
            "range": "stddev: 0.000031919836174715633",
            "extra": "mean: 20.94160940939672 usec\nrounds: 12243"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18300.020091125218,
            "unit": "iter/sec",
            "range": "stddev: 0.000003915219965765256",
            "extra": "mean: 54.64474875002789 usec\nrounds: 11801"
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
          "id": "54d0ae34a47317f9f02d932f161d7e03aa116dd6",
          "message": "chore(release): 2.2.0",
          "timestamp": "2026-08-05T15:16:25+02:00",
          "tree_id": "1816f29a99e6ebd00b780319a4fdb8bb39cb5365",
          "url": "https://github.com/mangrisano/cvewatcher/commit/54d0ae34a47317f9f02d932f161d7e03aa116dd6"
        },
        "date": 1785935819589,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 114317.48811852267,
            "unit": "iter/sec",
            "range": "stddev: 9.660634243688852e-7",
            "extra": "mean: 8.747567992074973 usec\nrounds: 21076"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 65184.04022894923,
            "unit": "iter/sec",
            "range": "stddev: 0.000026324625029005495",
            "extra": "mean: 15.34117855364057 usec\nrounds: 17961"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 25539.927819202097,
            "unit": "iter/sec",
            "range": "stddev: 0.000002469120576910685",
            "extra": "mean: 39.154378472759575 usec\nrounds: 12310"
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
          "id": "19d3546f50cc13e245822aec15897c566d545324",
          "message": "chore(release): 2.3.0\n\nCo-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>",
          "timestamp": "2026-08-05T16:07:33+02:00",
          "tree_id": "48acac3dc71420d75373e4980c5511bcbdf4797f",
          "url": "https://github.com/mangrisano/cvewatcher/commit/19d3546f50cc13e245822aec15897c566d545324"
        },
        "date": 1785938900024,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 79729.25052279621,
            "unit": "iter/sec",
            "range": "stddev: 0.0000019006551168621028",
            "extra": "mean: 12.542448266387249 usec\nrounds: 21775"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47407.68347592422,
            "unit": "iter/sec",
            "range": "stddev: 0.000025695812945643894",
            "extra": "mean: 21.093627165053224 usec\nrounds: 15704"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18179.86350758681,
            "unit": "iter/sec",
            "range": "stddev: 0.0000039831260159587355",
            "extra": "mean: 55.005913525295746 usec\nrounds: 11460"
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
          "id": "6762cddb9e64dcdafb64c6dad72f738c3e2272da",
          "message": "docs(readme): document registration gating, rate limiting, and session refresh\n\nThe 2.3.0 auth changes (closed-by-default sign-up, per-IP rate limits on\nlogin/register, silent session refresh) weren't reflected in the README.\n\nCo-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>",
          "timestamp": "2026-08-05T16:10:58+02:00",
          "tree_id": "73c39d77fb80ca96017712fdce1319f898fe85c4",
          "url": "https://github.com/mangrisano/cvewatcher/commit/6762cddb9e64dcdafb64c6dad72f738c3e2272da"
        },
        "date": 1785939093437,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 93656.81008343968,
            "unit": "iter/sec",
            "range": "stddev: 0.0000010307628126545692",
            "extra": "mean: 10.677280158368529 usec\nrounds: 19696"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 54178.91336533112,
            "unit": "iter/sec",
            "range": "stddev: 0.000029484524895553188",
            "extra": "mean: 18.457365382301965 usec\nrounds: 16662"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 20903.361733836526,
            "unit": "iter/sec",
            "range": "stddev: 0.000004421936670823901",
            "extra": "mean: 47.8391950889549 usec\nrounds: 10344"
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
          "id": "36750864cbb2a8166c29ffb1cee0cd910273fc6f",
          "message": "fix(db): run Alembic migrations automatically on startup against Postgres\n\ncreate_tables() only ever ran Base.metadata.create_all(), which creates\nmissing tables but never alters existing ones, and the Dockerfile's\n`alembic upgrade head` was commented out. An existing production deployment\nupgrading past a schema-changing release (e.g. the ecosystem column) would\nstart fine but 500 on first use of the new column until someone manually ran\nthe migration. app.database.init_schema() now runs `alembic upgrade head`\nfor Postgres on every startup; SQLite (dev/test) keeps create_all(), since\nthe migrations use Postgres-specific types.\n\nCo-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>",
          "timestamp": "2026-08-05T16:32:52+02:00",
          "tree_id": "4ccacd1a1e2db486178f818525cb4ea1b850a510",
          "url": "https://github.com/mangrisano/cvewatcher/commit/36750864cbb2a8166c29ffb1cee0cd910273fc6f"
        },
        "date": 1785940409667,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 88808.7217481529,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012322561463471594",
            "extra": "mean: 11.260155312626136 usec\nrounds: 19773"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47865.12994463389,
            "unit": "iter/sec",
            "range": "stddev: 0.000028385908002849924",
            "extra": "mean: 20.89203562503039 usec\nrounds: 14428"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18941.99273985103,
            "unit": "iter/sec",
            "range": "stddev: 0.0000028804573775591096",
            "extra": "mean: 52.79275595413751 usec\nrounds: 11715"
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
          "id": "a0781a99631212619fd80b25f1dda4367bc03a54",
          "message": "chore(release): 2.3.1\n\nCo-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>",
          "timestamp": "2026-08-05T16:33:47+02:00",
          "tree_id": "3ad2fc9e4ddc663bb9dcce2071aac1b6a0cb48e5",
          "url": "https://github.com/mangrisano/cvewatcher/commit/a0781a99631212619fd80b25f1dda4367bc03a54"
        },
        "date": 1785940459041,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 83997.30642768458,
            "unit": "iter/sec",
            "range": "stddev: 0.000001177740714024731",
            "extra": "mean: 11.905143659111562 usec\nrounds: 21732"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48488.12862727242,
            "unit": "iter/sec",
            "range": "stddev: 0.000028163288352152517",
            "extra": "mean: 20.62360475255678 usec\nrounds: 16286"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18512.955026701133,
            "unit": "iter/sec",
            "range": "stddev: 0.000003334726707053165",
            "extra": "mean: 54.0162280174994 usec\nrounds: 11657"
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
          "id": "d696a0ecd550f669be9d8be75558ea7af512ab0d",
          "message": "fix(db): stop Alembic from disabling app/uvicorn loggers on startup\n\ninit_schema() (added in 2.3.1) runs `alembic upgrade head` in-process on\nevery startup. alembic/env.py calls fileConfig(config.config_file_name) when\na config file is attached to the Config object, and fileConfig() defaults to\ndisable_existing_loggers=True. alembic.ini only declares root/sqlalchemy/\nalembic loggers, so this silently disabled every other logger in the process\nafter the first migration ran — including uvicorn.access, which is why HTTP\naccess logs vanished with no error after startup. Building the Config\nwithout a file (script_location set directly instead) skips fileConfig()\nentirely.\n\nCo-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>",
          "timestamp": "2026-08-05T17:02:22+02:00",
          "tree_id": "0f7abb5bf5798f7caab073136ea07b5dece16662",
          "url": "https://github.com/mangrisano/cvewatcher/commit/d696a0ecd550f669be9d8be75558ea7af512ab0d"
        },
        "date": 1785942187244,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 100539.06741721834,
            "unit": "iter/sec",
            "range": "stddev: 0.0000011878480947950781",
            "extra": "mean: 9.946382293861816 usec\nrounds: 19914"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 56236.278967840684,
            "unit": "iter/sec",
            "range": "stddev: 0.000026989908974389303",
            "extra": "mean: 17.782115359585944 usec\nrounds: 16895"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 22146.464818576413,
            "unit": "iter/sec",
            "range": "stddev: 0.000003252986923778193",
            "extra": "mean: 45.15393351453555 usec\nrounds: 11777"
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
          "id": "6a26748979a5c8fd5420c1a267abbbdb5eb0c61c",
          "message": "build: pin dependencies to compatible-release (~=) version ranges\n\nrequirements.txt and pyproject.toml used open-ended lower bounds\n(e.g. uvicorn[standard]>=0.35.0), so a fresh install/build could silently\npull a much newer major/minor version. That's exactly what happened while\ndebugging the previous fix: the Docker build resolved uvicorn 0.52.1 (17\nminor versions ahead of the locally installed 0.35.0), which behaved\ndifferently enough to cost real time to track down. Pinning to ~= locks\neach dependency to its current major.minor (or major, for two-segment\nversions like packaging/cvss) and only allows patch-level updates, trading\na bit of manual-bump maintenance for reproducible builds.\n\nCo-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>",
          "timestamp": "2026-08-05T17:58:03+02:00",
          "tree_id": "a131def44e515b5f007876cdda63690933915534",
          "url": "https://github.com/mangrisano/cvewatcher/commit/6a26748979a5c8fd5420c1a267abbbdb5eb0c61c"
        },
        "date": 1785945525848,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 112395.17255101097,
            "unit": "iter/sec",
            "range": "stddev: 7.663258679204344e-7",
            "extra": "mean: 8.897179276504481 usec\nrounds: 23249"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 62418.34222629107,
            "unit": "iter/sec",
            "range": "stddev: 0.00002090449880460333",
            "extra": "mean: 16.02093173789535 usec\nrounds: 19513"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 23738.429311659926,
            "unit": "iter/sec",
            "range": "stddev: 0.0000020710389885272557",
            "extra": "mean: 42.12578628817773 usec\nrounds: 14688"
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
          "id": "24c2c0e968405cd549f3bba3010fe86552f742a5",
          "message": "feat(landing): add GitHub Sponsors section",
          "timestamp": "2026-08-06T09:58:00+02:00",
          "tree_id": "483a4acbc09317d9d1c6f2e02ea51f2bc44d6ea4",
          "url": "https://github.com/mangrisano/cvewatcher/commit/24c2c0e968405cd549f3bba3010fe86552f742a5"
        },
        "date": 1786003809282,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 79488.78320896126,
            "unit": "iter/sec",
            "range": "stddev: 0.0000025615649593273556",
            "extra": "mean: 12.580391341142883 usec\nrounds: 21273"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47187.60663941267,
            "unit": "iter/sec",
            "range": "stddev: 0.000023084593460344924",
            "extra": "mean: 21.192005088148857 usec\nrounds: 16509"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 17625.72419221554,
            "unit": "iter/sec",
            "range": "stddev: 0.000004043370411464627",
            "extra": "mean: 56.73525746202549 usec\nrounds: 10654"
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
          "id": "d1d090e59f12deff88595aa8731e07c077a81904",
          "message": "fix(assets): drop untriaged findings when an asset's identity changes\n\nChanging name, version, CPE or ecosystem left the old version's findings\nlinked, so digests and metrics kept reporting CVEs that no longer apply.\nOpen findings are now dropped on such a change and the next monitoring cycle\nre-links the ones that still apply; triaged findings keep status and notes.",
          "timestamp": "2026-09-29T19:43:15+02:00",
          "tree_id": "515d4f285d9c6c78fa6146c0ac2ae42523db79a3",
          "url": "https://github.com/mangrisano/cvewatcher/commit/d1d090e59f12deff88595aa8731e07c077a81904"
        },
        "date": 1790703822570,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 116890.61805041207,
            "unit": "iter/sec",
            "range": "stddev: 8.878096545624841e-7",
            "extra": "mean: 8.555006523865964 usec\nrounds: 39547"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 68374.36265954853,
            "unit": "iter/sec",
            "range": "stddev: 0.00000226972655635135",
            "extra": "mean: 14.625364845873987 usec\nrounds: 20595"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 26226.793652123284,
            "unit": "iter/sec",
            "range": "stddev: 0.000002098991324593799",
            "extra": "mean: 38.128946041371755 usec\nrounds: 15864"
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
          "id": "b309e76f38c10aa7c418e47542fc4622f606690b",
          "message": "fix(auth): fail closed on Redis outages and prune the DB blocklist\n\nWith REDIS_URL set, a worker that could not ping Redis at startup fell\nback to the database blocklist for its whole lifetime and never saw\nrevocations stored in Redis, accepting revoked tokens. Redis is now the only\nbackend when configured; errors raise BlocklistUnavailableError, served as\n503, and the client reconnects on its own.\n\nThe database backend never pruned expired rows (purge_expired_tokens had no\ncaller) and a duplicate revoke raced into an IntegrityError. Expired rows\nare now deleted on every revocation and the duplicate is ignored.",
          "timestamp": "2026-09-29T20:24:15+02:00",
          "tree_id": "a8cae0662d21caad81fa8ac233c3eaa4eb172c56",
          "url": "https://github.com/mangrisano/cvewatcher/commit/b309e76f38c10aa7c418e47542fc4622f606690b"
        },
        "date": 1790706383926,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 117705.38787521642,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012779261505196162",
            "extra": "mean: 8.495787814404341 usec\nrounds: 26835"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 66033.92554083036,
            "unit": "iter/sec",
            "range": "stddev: 0.000018464280842036372",
            "extra": "mean: 15.14373092027788 usec\nrounds: 21135"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 25937.798245266633,
            "unit": "iter/sec",
            "range": "stddev: 0.000003943579308562594",
            "extra": "mean: 38.55377355256008 usec\nrounds: 15752"
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
          "id": "043a910d5f2f078bbc03f997aca14043e123ce3e",
          "message": "chore(release): 2.4.0",
          "timestamp": "2026-09-29T20:27:59+02:00",
          "tree_id": "01ff65d7f4204bc5004091767873e5a580959ab1",
          "url": "https://github.com/mangrisano/cvewatcher/commit/043a910d5f2f078bbc03f997aca14043e123ce3e"
        },
        "date": 1790706505858,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 157321.13899266874,
            "unit": "iter/sec",
            "range": "stddev: 6.804340519658487e-7",
            "extra": "mean: 6.356424867014219 usec\nrounds: 47935"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 86097.262452076,
            "unit": "iter/sec",
            "range": "stddev: 0.00002040329462129359",
            "extra": "mean: 11.614771149740404 usec\nrounds: 21726"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 34298.64582620766,
            "unit": "iter/sec",
            "range": "stddev: 0.000002720150486860628",
            "extra": "mean: 29.155670024613567 usec\nrounds: 18265"
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
          "id": "8b9378636bdd58105b47629f1f64abbe5f1aa3f7",
          "message": "refactor(config): read all settings from one typed Settings object\n\nAbout 40 os.getenv calls were spread over 13 modules, each with its own\ndefault and parsing (three copies of _is_truthy, ad-hoc int() casts).\napp/config.py now declares every setting once with pydantic-settings and\nget_settings() (cached) is the only way modules read configuration.\n\nMalformed values (e.g. MONITOR_ENABLED=maybe, NVD_MAX_CONCURRENCY=0) now\nstop startup with a validation error instead of silently becoming false or\nbeing ignored; empty variables still fall back to the default. Adds\npydantic-settings to the dependencies.",
          "timestamp": "2026-09-29T21:05:18+02:00",
          "tree_id": "147316ed4c1c958b6622d749942300b852f8f098",
          "url": "https://github.com/mangrisano/cvewatcher/commit/8b9378636bdd58105b47629f1f64abbe5f1aa3f7"
        },
        "date": 1790713088897,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 86310.7712411622,
            "unit": "iter/sec",
            "range": "stddev: 0.0000013187552378831",
            "extra": "mean: 11.586039443511464 usec\nrounds: 37953"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48875.21435892676,
            "unit": "iter/sec",
            "range": "stddev: 0.00000271152775650136",
            "extra": "mean: 20.460268320385506 usec\nrounds: 17576"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18663.753468134375,
            "unit": "iter/sec",
            "range": "stddev: 0.0000033907037919745553",
            "extra": "mean: 53.57979045894243 usec\nrounds: 11592"
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
          "id": "f2d8476176b2f4981b55efe64113acf13755ed82",
          "message": "fix(types): accept ORM asset ids in FindingRepository\n\nCI's pyright step failed after the repository refactor: the 1.x-style\nmodels type Asset.id as a Column, which is not assignable to the UUID the\nrepository methods declared. The asset id is now typed UUID | Column.",
          "timestamp": "2026-09-29T22:23:42+02:00",
          "tree_id": "f3282e50461b4adc05bf39009d24e09c38ce626a",
          "url": "https://github.com/mangrisano/cvewatcher/commit/f2d8476176b2f4981b55efe64113acf13755ed82"
        },
        "date": 1790713528365,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 87819.26426100874,
            "unit": "iter/sec",
            "range": "stddev: 0.000001454511663501447",
            "extra": "mean: 11.387023205157895 usec\nrounds: 26632"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48261.319629181664,
            "unit": "iter/sec",
            "range": "stddev: 0.000002689834234293042",
            "extra": "mean: 20.720527488339556 usec\nrounds: 17371"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18553.275965968038,
            "unit": "iter/sec",
            "range": "stddev: 0.0000035129586072164817",
            "extra": "mean: 53.89883715599785 usec\nrounds: 11772"
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
          "id": "b4392efd2c5160e398d6361d1fcb01cf1bd56627",
          "message": "chore(release): 2.5.0",
          "timestamp": "2026-09-29T22:27:44+02:00",
          "tree_id": "8d3a878a8daf3fa311672ad1d7d8ba32a5973ad3",
          "url": "https://github.com/mangrisano/cvewatcher/commit/b4392efd2c5160e398d6361d1fcb01cf1bd56627"
        },
        "date": 1790713699736,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 93743.33191632682,
            "unit": "iter/sec",
            "range": "stddev: 0.0000011018556076638347",
            "extra": "mean: 10.667425400374904 usec\nrounds: 29913"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48437.35508666366,
            "unit": "iter/sec",
            "range": "stddev: 0.0000029975600664952835",
            "extra": "mean: 20.645223055858633 usec\nrounds: 15727"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18784.216723322905,
            "unit": "iter/sec",
            "range": "stddev: 0.0000029692006072802142",
            "extra": "mean: 53.23618305353012 usec\nrounds: 12215"
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
          "id": "a74c538f6767ecd64a5a01a807b046bb69c870f9",
          "message": "chore(release): 2.6.0",
          "timestamp": "2026-09-29T22:44:15+02:00",
          "tree_id": "8c64754eb0a358fd26d85680e38fdb1081bd6b38",
          "url": "https://github.com/mangrisano/cvewatcher/commit/a74c538f6767ecd64a5a01a807b046bb69c870f9"
        },
        "date": 1790714681297,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 91765.56070652536,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012837966835887368",
            "extra": "mean: 10.897334384498466 usec\nrounds: 38052"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 49074.456515882644,
            "unit": "iter/sec",
            "range": "stddev: 0.000003295765295626064",
            "extra": "mean: 20.377199687914143 usec\nrounds: 16020"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18516.08263811276,
            "unit": "iter/sec",
            "range": "stddev: 0.0000029978249036434902",
            "extra": "mean: 54.00710396170086 usec\nrounds: 11687"
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
          "id": "9aac2ae85246695fbe1b4d3d64ede4b53f1f4fd1",
          "message": "chore(release): 2.6.1",
          "timestamp": "2026-09-29T23:05:14+02:00",
          "tree_id": "4ad97d01a5388e1ce5a9a5450029307da71416b1",
          "url": "https://github.com/mangrisano/cvewatcher/commit/9aac2ae85246695fbe1b4d3d64ede4b53f1f4fd1"
        },
        "date": 1790715944626,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 93396.08134315201,
            "unit": "iter/sec",
            "range": "stddev: 0.0000013591789630862585",
            "extra": "mean: 10.707087338341761 usec\nrounds: 37120"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 49024.168581080914,
            "unit": "iter/sec",
            "range": "stddev: 0.0000030985471600988975",
            "extra": "mean: 20.398102179868758 usec\nrounds: 16882"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 19062.345751679994,
            "unit": "iter/sec",
            "range": "stddev: 0.0000024687423371401026",
            "extra": "mean: 52.45944088029504 usec\nrounds: 12314"
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
          "id": "17d3d5e980986fec508b437733e33273bebbbeea",
          "message": "chore(release): 2.6.2",
          "timestamp": "2026-09-30T09:55:10+02:00",
          "tree_id": "8229617404e8bc416150cd29e6b605055587c337",
          "url": "https://github.com/mangrisano/cvewatcher/commit/17d3d5e980986fec508b437733e33273bebbbeea"
        },
        "date": 1790754937301,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 119041.2116684767,
            "unit": "iter/sec",
            "range": "stddev: 0.0000010815491957664835",
            "extra": "mean: 8.400452129006766 usec\nrounds: 39126"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 61095.48018397664,
            "unit": "iter/sec",
            "range": "stddev: 0.0000029512458536975803",
            "extra": "mean: 16.367822905863136 usec\nrounds: 20283"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 24286.309404752417,
            "unit": "iter/sec",
            "range": "stddev: 0.00000216606018951641",
            "extra": "mean: 41.17546158760199 usec\nrounds: 15659"
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
          "id": "9d196e0aba4e8377efd7a9aba6612d82d399a48d",
          "message": "chore(release): 2.7.0",
          "timestamp": "2026-09-30T10:43:57+02:00",
          "tree_id": "401ec4ba789476dbaf4bbf0ea673f791c0b21366",
          "url": "https://github.com/mangrisano/cvewatcher/commit/9d196e0aba4e8377efd7a9aba6612d82d399a48d"
        },
        "date": 1790757867299,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 87203.03036029388,
            "unit": "iter/sec",
            "range": "stddev: 0.0000018181102537473904",
            "extra": "mean: 11.4674913918511 usec\nrounds: 39846"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 49133.53542023161,
            "unit": "iter/sec",
            "range": "stddev: 0.000002599420507170946",
            "extra": "mean: 20.35269783554456 usec\nrounds: 19496"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18631.112974693628,
            "unit": "iter/sec",
            "range": "stddev: 0.000003475308994528093",
            "extra": "mean: 53.67365875341348 usec\nrounds: 12258"
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
          "id": "413b80d78ff77a77ce3c3234a24aa271c75d0687",
          "message": "chore(release): 2.7.1",
          "timestamp": "2026-09-30T11:26:33+02:00",
          "tree_id": "92806daf8192cf0d4a773756bfef6735b1c63c47",
          "url": "https://github.com/mangrisano/cvewatcher/commit/413b80d78ff77a77ce3c3234a24aa271c75d0687"
        },
        "date": 1790760423143,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 84155.65222002307,
            "unit": "iter/sec",
            "range": "stddev: 0.0000017669451927847616",
            "extra": "mean: 11.882743150579149 usec\nrounds: 24929"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47703.510842150885,
            "unit": "iter/sec",
            "range": "stddev: 0.0000026384580086771875",
            "extra": "mean: 20.96281766993969 usec\nrounds: 17227"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18232.911914831286,
            "unit": "iter/sec",
            "range": "stddev: 0.0000036882113093024784",
            "extra": "mean: 54.84587457402047 usec\nrounds: 12031"
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
          "id": "d2efb7dea4931179daba62ecf4ed1340f1447265",
          "message": "chore(release): 2.8.0",
          "timestamp": "2026-09-30T13:08:17+02:00",
          "tree_id": "901c592f3b54da106bda08c0f11907eb5771e0f9",
          "url": "https://github.com/mangrisano/cvewatcher/commit/d2efb7dea4931179daba62ecf4ed1340f1447265"
        },
        "date": 1790766525095,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 90557.44400320767,
            "unit": "iter/sec",
            "range": "stddev: 0.0000012193066863430177",
            "extra": "mean: 11.042714500252222 usec\nrounds: 39282"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 49080.69820937991,
            "unit": "iter/sec",
            "range": "stddev: 0.0000030600437043641815",
            "extra": "mean: 20.374608277452907 usec\nrounds: 17469"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18664.779679805462,
            "unit": "iter/sec",
            "range": "stddev: 0.0000035378667889820155",
            "extra": "mean: 53.57684457866704 usec\nrounds: 11916"
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
          "id": "56a8b058a9fc5078d8272722bc3b196d7ceaab38",
          "message": "chore(release): 2.9.0",
          "timestamp": "2026-09-30T13:48:21+02:00",
          "tree_id": "65724129ab492a3a15d86c22c47c9a4fee468aa5",
          "url": "https://github.com/mangrisano/cvewatcher/commit/56a8b058a9fc5078d8272722bc3b196d7ceaab38"
        },
        "date": 1790768927968,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 178457.52450008804,
            "unit": "iter/sec",
            "range": "stddev: 5.614932189307561e-7",
            "extra": "mean: 5.603574311597641 usec\nrounds: 59015"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 89945.89137770346,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014745117754761493",
            "extra": "mean: 11.117795206462185 usec\nrounds: 32252"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 35822.938518848016,
            "unit": "iter/sec",
            "range": "stddev: 0.0000014205304329332353",
            "extra": "mean: 27.915074568041263 usec\nrounds: 22570"
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
          "id": "e4aa8b173da0ed01ee74602b81e3a54f8d5ac35b",
          "message": "chore(release): 2.9.1",
          "timestamp": "2026-09-30T14:10:33+02:00",
          "tree_id": "8339292a67452a92232d60e8693b1b985f5fec80",
          "url": "https://github.com/mangrisano/cvewatcher/commit/e4aa8b173da0ed01ee74602b81e3a54f8d5ac35b"
        },
        "date": 1790770261662,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 89047.29658957348,
            "unit": "iter/sec",
            "range": "stddev: 0.000001393733721946016",
            "extra": "mean: 11.229987189943392 usec\nrounds: 37314"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48913.33950228191,
            "unit": "iter/sec",
            "range": "stddev: 0.0000031028975313981987",
            "extra": "mean: 20.444320714461703 usec\nrounds: 17408"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18661.601517057683,
            "unit": "iter/sec",
            "range": "stddev: 0.000004327241438706459",
            "extra": "mean: 53.58596897945482 usec\nrounds: 11573"
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
          "id": "abc42c20c64530e1353b320aa4dc641428c53ac4",
          "message": "chore(release): 2.10.0",
          "timestamp": "2026-09-30T14:58:35+02:00",
          "tree_id": "9a75302468cadf27508f8abc6b8826bc941775d5",
          "url": "https://github.com/mangrisano/cvewatcher/commit/abc42c20c64530e1353b320aa4dc641428c53ac4"
        },
        "date": 1790773145139,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 86797.87152894687,
            "unit": "iter/sec",
            "range": "stddev: 0.000001245511504682936",
            "extra": "mean: 11.52101984052112 usec\nrounds: 37751"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 47416.29839147291,
            "unit": "iter/sec",
            "range": "stddev: 0.0000032513674266714465",
            "extra": "mean: 21.089794731421602 usec\nrounds: 17007"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18737.30769908651,
            "unit": "iter/sec",
            "range": "stddev: 0.000002985259246583244",
            "extra": "mean: 53.369460333340875 usec\nrounds: 11874"
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
          "id": "d5c358054e61a5c1e4c66a10c67d0d3438f8f5e4",
          "message": "chore(release): 2.10.1",
          "timestamp": "2026-09-30T15:15:37+02:00",
          "tree_id": "38bf3f742c406fe86d558286594fbc003549a21a",
          "url": "https://github.com/mangrisano/cvewatcher/commit/d5c358054e61a5c1e4c66a10c67d0d3438f8f5e4"
        },
        "date": 1790774165933,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 87519.7066342074,
            "unit": "iter/sec",
            "range": "stddev: 0.0000013773729983411472",
            "extra": "mean: 11.425998080404288 usec\nrounds: 37508"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 49617.70351838208,
            "unit": "iter/sec",
            "range": "stddev: 0.00000334530801967194",
            "extra": "mean: 20.15409680598228 usec\nrounds: 17251"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18694.31311152462,
            "unit": "iter/sec",
            "range": "stddev: 0.0000034882049716435467",
            "extra": "mean: 53.49220343289974 usec\nrounds: 11827"
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
          "id": "b0e6b56a25adad5c00d56a7491720abe419c5c8b",
          "message": "chore(release): 2.11.0",
          "timestamp": "2026-09-30T17:18:45+02:00",
          "tree_id": "f3aa4e2f7dafedb99a2de2466cd1c2bd7b5442dc",
          "url": "https://github.com/mangrisano/cvewatcher/commit/b0e6b56a25adad5c00d56a7491720abe419c5c8b"
        },
        "date": 1790781561394,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 95744.12241352684,
            "unit": "iter/sec",
            "range": "stddev: 7.874363223410727e-7",
            "extra": "mean: 10.444505362751322 usec\nrounds: 38786"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 53377.131774823436,
            "unit": "iter/sec",
            "range": "stddev: 0.0000029055873185026625",
            "extra": "mean: 18.73461474510463 usec\nrounds: 19125"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 20303.80493707169,
            "unit": "iter/sec",
            "range": "stddev: 0.0000021604886296318167",
            "extra": "mean: 49.25185220697971 usec\nrounds: 13140"
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
          "id": "2a61cf9dbe6589ba1b16266538b5bb96efe7aca2",
          "message": "chore(release): 2.12.0",
          "timestamp": "2026-09-30T18:40:22+02:00",
          "tree_id": "de6281d47318a3eb40a53668c237b1a00a162361",
          "url": "https://github.com/mangrisano/cvewatcher/commit/2a61cf9dbe6589ba1b16266538b5bb96efe7aca2"
        },
        "date": 1790786451570,
        "tool": "pytest",
        "benches": [
          {
            "name": "benchmarks/bench_perf.py::test_cpe_matches_name",
            "value": 84842.39343491581,
            "unit": "iter/sec",
            "range": "stddev: 0.0000013389820135801181",
            "extra": "mean: 11.786560462454643 usec\nrounds: 38404"
          },
          {
            "name": "benchmarks/bench_perf.py::test_version_affected",
            "value": 48758.695889028975,
            "unit": "iter/sec",
            "range": "stddev: 0.0000030681114760681154",
            "extra": "mean: 20.50916214568008 usec\nrounds: 18027"
          },
          {
            "name": "benchmarks/bench_perf.py::test_match_pipeline",
            "value": 18675.45301729522,
            "unit": "iter/sec",
            "range": "stddev: 0.000002975364049669182",
            "extra": "mean: 53.54622450517834 usec\nrounds: 11973"
          }
        ]
      }
    ]
  }
}