import pytest

from app.services.sbom import MAX_COMPONENTS, SbomError, parse_purl, parse_sbom


def _login(client, username):
    email = f"{username}@example.com"
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": "Password123"},
    )
    token = client.post(
        "/auth/login", json={"email": email, "password": "Password123"}
    ).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _cyclonedx(*purls, project="shop"):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": project}},
        "components": [{"name": p.split("/")[-1], "purl": p} for p in purls],
    }


@pytest.mark.parametrize(
    "purl, expected",
    [
        ("pkg:pypi/requests@2.31.0", ("pypi", "requests", "2.31.0")),
        ("pkg:npm/%40angular/core@17.0.1", ("npm", "@angular/core", "17.0.1")),
        ("pkg:npm/@angular/core@17.0.1", ("npm", "@angular/core", "17.0.1")),
        ("pkg:npm/@angular/core", ("npm", "@angular/core", None)),
        (
            "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar",
            ("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ),
        (
            "pkg:golang/github.com/gorilla/mux@v1.8.0#sub",
            ("golang", "github.com/gorilla/mux", "v1.8.0"),
        ),
        ("pkg:PyPI/Django@4.2", ("pypi", "Django", "4.2")),
        ("requests==2.31.0", None),
        ("pkg:pypi/", None),
    ],
)
def test_parse_purl(purl, expected):
    assert parse_purl(purl) == expected


def test_parse_cyclonedx_maps_ecosystems_and_nested_components():
    document = _cyclonedx("pkg:pypi/flask@3.0.0", "pkg:cargo/serde@1.0.190")
    document["components"][0]["components"] = [
        {"name": "jinja2", "purl": "pkg:pypi/jinja2@3.1.2"}
    ]
    document["components"].append({"name": "libfoo"})
    document["components"].append({"name": "x", "purl": "pkg:deb/debian/curl@7.88"})

    sbom = parse_sbom(document)

    assert sbom.project == "shop"
    assert [(p.name, p.version, p.ecosystem) for p in sbom.packages] == [
        ("flask", "3.0.0", "PyPI"),
        ("jinja2", "3.1.2", "PyPI"),
        ("serde", "1.0.190", "crates.io"),
    ]
    assert sbom.unsupported == ["libfoo", "pkg:deb/debian/curl@7.88"]


def test_parse_spdx_reads_purl_external_refs():
    document = {
        "spdxVersion": "SPDX-2.3",
        "name": "api-server",
        "packages": [
            {
                "name": "lodash",
                "externalRefs": [
                    {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a:x"},
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:npm/lodash@4.17.20",
                    },
                ],
            },
            {"name": "api-server"},
        ],
    }
    sbom = parse_sbom(document)
    assert sbom.project == "api-server"
    assert [(p.name, p.version, p.ecosystem) for p in sbom.packages] == [
        ("lodash", "4.17.20", "npm")
    ]
    assert sbom.unsupported == ["api-server"]


def test_parse_sbom_drops_duplicate_packages():
    sbom = parse_sbom(_cyclonedx("pkg:pypi/six@1.16.0", "pkg:pypi/six@1.16.0"))
    assert len(sbom.packages) == 1


@pytest.mark.parametrize("document", [[], {"foo": "bar"}, {"bomFormat": "Other"}])
def test_parse_sbom_rejects_unknown_documents(document):
    with pytest.raises(SbomError):
        parse_sbom(document)


def test_parse_sbom_rejects_too_many_components():
    purls = [f"pkg:pypi/p{i}@1.0" for i in range(MAX_COMPONENTS + 1)]
    with pytest.raises(SbomError, match="more than"):
        parse_sbom(_cyclonedx(*purls))


def test_import_sbom_creates_assets_and_skips_existing(client):
    headers = _login(client, "sbomuser")
    client.post(
        "/assets/",
        json={"name": "requests", "version": "2.31.0", "ecosystem": "PyPI"},
        headers=headers,
    )
    document = _cyclonedx(
        "pkg:pypi/requests@2.31.0",
        "pkg:npm/lodash@4.17.20",
        f"pkg:pypi/{'x' * 101}@1.0",
        "pkg:deb/debian/curl@7.88",
    )

    response = client.post("/assets/import-sbom", json=document, headers=headers)

    assert response.status_code == 200
    assert response.json() == {
        "project": "shop",
        "created": 1,
        "skipped_existing": ["requests@2.31.0"],
        "skipped_invalid": [f"{'x' * 101}@1.0"],
        "unsupported": ["pkg:deb/debian/curl@7.88"],
    }
    assets = client.get("/assets/", headers=headers).json()
    lodash = next(a for a in assets if a["name"] == "lodash")
    assert lodash["ecosystem"] == "npm"
    assert lodash["description"] == "Imported from SBOM: shop"

    # Importing the same SBOM again creates nothing new.
    again = client.post("/assets/import-sbom", json=document, headers=headers).json()
    assert again["created"] == 0


def test_imported_assets_page_without_repeats(client):
    headers = _login(client, "sbompager")
    purls = [f"pkg:pypi/page{i}@1.0" for i in range(150)]
    client.post("/assets/import-sbom", json=_cyclonedx(*purls), headers=headers)
    # Imported together, the assets share created_at: paging must stay stable.
    names = [
        a["name"]
        for offset in (0, 100)
        for a in client.get(
            f"/assets/?limit=100&offset={offset}", headers=headers
        ).json()
    ]
    assert sorted(names) == sorted(f"page{i}" for i in range(150))


def test_import_sbom_assets_belong_to_the_importer(client):
    alice = _login(client, "sbomalice")
    bob = _login(client, "sbombob")
    client.post(
        "/assets/import-sbom", json=_cyclonedx("pkg:pypi/rich@13.0.0"), headers=alice
    )
    assert all(a["name"] != "rich" for a in client.get("/assets/", headers=bob).json())


def test_import_sbom_rejects_bad_input(client):
    headers = _login(client, "sbombad")
    post = client.post
    assert (
        post("/assets/import-sbom", content=b"{nope", headers=headers).status_code
        == 400
    )
    assert (
        post("/assets/import-sbom", json={"a": 1}, headers=headers).status_code == 400
    )
    too_big = b" " * (5 * 1024 * 1024 + 1)
    assert (
        post("/assets/import-sbom", content=too_big, headers=headers).status_code == 413
    )
    assert post("/assets/import-sbom", json=_cyclonedx()).status_code == 401
