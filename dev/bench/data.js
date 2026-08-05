window.BENCHMARK_DATA = {
  "lastUpdate": 1785939093917,
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
      }
    ]
  }
}