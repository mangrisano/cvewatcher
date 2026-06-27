def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_register_login_and_profile(client):
    response = client.post(
        "/auth/register",
        json={
            "username": "alice",
            "email": "alice@example.com",
            "password": "Password123",
        },
    )
    assert response.status_code == 200

    response = client.post(
        "/auth/login",
        json={"email": "alice@example.com", "password": "Password123"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    token = body["access_token"]

    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/user", headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == "alice@example.com"


def test_register_rejects_short_password(client):
    response = client.post(
        "/auth/register",
        json={"username": "shorty", "email": "shorty@example.com", "password": "short"},
    )
    assert response.status_code == 422


def test_login_with_wrong_password(client):
    client.post(
        "/auth/register",
        json={
            "username": "bob",
            "email": "bob@example.com",
            "password": "Password123",
        },
    )
    response = client.post(
        "/auth/login",
        json={"email": "bob@example.com", "password": "wrongpassword"},
    )
    assert response.status_code == 401


def test_asset_crud_flow(client):
    client.post(
        "/auth/register",
        json={
            "username": "carol",
            "email": "carol@example.com",
            "password": "Password123",
        },
    )
    token = client.post(
        "/auth/login",
        json={"email": "carol@example.com", "password": "Password123"},
    ).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    response = client.post(
        "/assets/", headers=headers, json={"name": "nginx", "version": "1.20.0"}
    )
    assert response.status_code == 200
    asset_id = response.json()["id"]

    # Creating the same asset twice is rejected.
    response = client.post(
        "/assets/", headers=headers, json={"name": "nginx", "version": "1.20.0"}
    )
    assert response.status_code == 400

    response = client.get("/assets/", headers=headers)
    assert response.status_code == 200
    assert any(asset["id"] == asset_id for asset in response.json())

    response = client.patch(
        f"/assets/{asset_id}",
        headers=headers,
        json={"name": "nginx", "version": "1.21.0", "description": "web server"},
    )
    assert response.status_code == 200
    assert response.json()["version"] == "1.21.0"

    response = client.delete(f"/assets/{asset_id}", headers=headers)
    assert response.status_code == 204


def test_assets_require_authentication(client):
    response = client.get("/assets/")
    assert response.status_code in (401, 403)
