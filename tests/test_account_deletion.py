"""Deleting your own account, with everything that belongs to it."""

from app.database.connection import SessionLocal
from app.database.models import CVE, Asset, AssetCVE, NotificationPreference, User
from app.routes import user as user_routes

PASSWORD = "Password123"


def _register_and_login(client, username):
    email = f"{username}@example.com"
    client.post(
        "/auth/register",
        json={"username": username, "email": email, "password": PASSWORD},
    )
    token = client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    ).json()["access_token"]
    return email, {"Authorization": f"Bearer {token}"}


def _delete(client, headers, password=PASSWORD):
    return client.request(
        "DELETE", "/user", json={"password": password}, headers=headers
    )


def test_deleting_the_account_removes_its_data_and_sessions(client):
    email, headers = _register_and_login(client, "delme")
    other_email, other_headers = _register_and_login(client, "keepme")
    cve_id = "CVE-DEL-0001"
    with SessionLocal() as db:
        mine = Asset(name="nginx", version="1.0", user_email=email)
        theirs = Asset(name="nginx", version="1.0", user_email=other_email)
        db.add_all([mine, theirs, CVE(id=cve_id, severity="HIGH")])
        db.commit()
        db.add_all(
            [
                AssetCVE(asset_id=mine.id, cve_id=cve_id, status="open"),
                AssetCVE(asset_id=theirs.id, cve_id=cve_id, status="open"),
            ]
        )
        user = db.query(User).filter(User.email == email).one()
        db.add(NotificationPreference(user_id=user.id))
        db.commit()
        mine_id, theirs_id, user_id = mine.id, theirs.id, user.id

    assert _delete(client, headers).status_code == 200

    with SessionLocal() as db:
        assert db.query(User).filter(User.email == email).count() == 0
        assert db.query(Asset).filter(Asset.user_email == email).count() == 0
        assert db.query(AssetCVE).filter(AssetCVE.asset_id == mine_id).count() == 0
        assert db.get(NotificationPreference, user_id) is None
        # Other people's data and the shared CVE catalogue stay.
        assert db.query(AssetCVE).filter(AssetCVE.asset_id == theirs_id).count() == 1
        assert db.get(CVE, cve_id) is not None
        db.query(AssetCVE).filter(AssetCVE.asset_id == theirs_id).delete()
        db.query(Asset).filter(Asset.id == theirs_id).delete()
        db.query(CVE).filter(CVE.id == cve_id).delete()
        db.commit()

    assert client.get("/user", headers=headers).status_code == 401
    assert client.get("/user", headers=other_headers).status_code == 200
    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 401


def test_the_password_is_required_to_delete(client):
    _, headers = _register_and_login(client, "delwrong")
    assert _delete(client, headers, password="Wrong12345").status_code == 400
    assert client.get("/user", headers=headers).status_code == 200
    user_routes._password_rate_limiter.reset("delwrong@example.com")


def test_the_owner_is_told_by_email(client, monkeypatch):
    sent = []
    monkeypatch.setattr(user_routes, "smtp_config", lambda: {"host": "smtp"})
    monkeypatch.setattr(user_routes, "send_account_deleted_notice", sent.append)
    _, headers = _register_and_login(client, "delmail")
    assert _delete(client, headers).status_code == 200
    assert sent == ["delmail@example.com"]
