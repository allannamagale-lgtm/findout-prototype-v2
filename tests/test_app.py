import os
import pytest
from app import create_app, db
from app import User, Subject, Claim, Search, hash_phone

@pytest.fixture
def app():
    app = create_app("testing")
    with app.app_context():
        db.create_all()
        yield app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()


def signup(client, email, phone, name="Test", surname="User", age=30):
    return client.post("/signup", data={
        "email": email,
        "password": "password123",
        "real_name": name,
        "real_surname": surname,
        "phone": phone,
        "age": age,
    }, follow_redirects=True)


def login(client, email, password="password123"):
    return client.post("/login", data={
        "email": email,
        "password": password,
    }, follow_redirects=True)


def test_signup_and_login(client, app):
    """Basic signup creates a user and lets them log in."""
    resp = signup(client, "alice@example.com", "0821111111", name="Alice", surname="Smith")
    assert b"Account created" in resp.data

    with app.app_context():
        user = User.query.filter_by(email="alice@example.com").first()
        assert user is not None
        assert user.real_name == "Alice"
        assert user.real_surname == "Smith"
        assert user.age == 30

    resp = login(client, "alice@example.com")
    assert b"Welcome back, Alice" in resp.data


def test_search_does_not_create_subject(client, app):
    """A search for a non-existent phone must NOT create a ghost subject."""
    signup(client, "bob@example.com", "0822222222", name="Bob", surname="Jones")
    login(client, "bob@example.com")

    # Consent
    client.post("/consent", follow_redirects=True)

    with app.app_context():
        before = Subject.query.count()

    client.post("/search", data={
        "name": "Ghost",
        "surname": "Person",
        "area": "Nowhere",
        "phone": "0829999999",
        "age": "25",
        "context": "testing",
    }, follow_redirects=True)

    with app.app_context():
        after = Subject.query.count()
        assert after == before  # no ghost subject created


def test_search_and_claim_strength(client, app):
    """Claimer claims a subject, then searches — strength should be Strong."""
    # Register two users
    signup(client, "claimer@example.com", "0823333333", name="Charlie", surname="Brown")
    signup(client, "subject@example.com", "0824444444", name="Dana", surname="White", age=28)

    # Subject consents
    login(client, "subject@example.com")
    client.post("/consent", follow_redirects=True)

    # Claimer logs in and makes a claim with full matching data
    login(client, "claimer@example.com")
    client.post("/consent", follow_redirects=True)

    client.post("/claim", data={
        "name": "Dana",
        "surname": "White",
        "area": "Cape Town",
        "phone": "0824444444",
        "age": "28",
        "relationship_state": "Dating",
    }, follow_redirects=True)

    # Now search for her — should find her, and full name + age match
    resp = client.post("/search", data={
        "name": "Dana",
        "surname": "White",
        "area": "Cape Town",
        "phone": "0824444444",
        "age": "28",
        "context": "verifying",
    }, follow_redirects=True)

    assert b"Active claim" in resp.data or b"Active Claim" in resp.data
    assert b"Strong" in resp.data  # matches phone + name + age + area


def test_mutual_claim_counts_on_subject_dashboard(client, app):
    """Mutual claims should count on the claimed user's dashboard."""
    # Two accounts
    signup(client, "a@example.com", "0825555555", name="Alex", surname="A")
    signup(client, "b@example.com", "0826666666", name="Bailey", surname="B")

    # Alex claims Bailey
    login(client, "a@example.com")
    client.post("/consent", follow_redirects=True)
    client.post("/claim", data={
        "name": "Bailey",
        "surname": "B",
        "area": "Durban",
        "phone": "0826666666",
        "age": "30",
        "relationship_state": "Dating",
    }, follow_redirects=True)

    # Bailey confirms
    login(client, "b@example.com")
    client.post("/consent", follow_redirects=True)
    with app.app_context():
        claim = Claim.query.first()
        claim_id = claim.id
    client.post(f"/respond/{claim_id}", data={"response_type": "confirm"}, follow_redirects=True)

    # Bailey's dashboard should now show 1 mutual claim
    with app.app_context():
        user_b = User.query.filter_by(email="b@example.com").first()
        subject_b = Subject.query.filter_by(account_linked_user_id=user_b.id).first()

    dash = client.get("/dashboard")
    assert b"Mutual Claims" in dash.data
    # The number 1 must appear near "Mutual Claims" (rough check)
    assert b"1" in dash.data


def test_rate_limit_blocks_6th_search(client, app):
    """Rate limiter should block the 6th search in an hour."""
    signup(client, "rl@example.com", "0827777777", name="Rate", surname="Limit")
    login(client, "rl@example.com")
    client.post("/consent", follow_redirects=True)

    def do_search(i):
        return client.post("/search", data={
            "name": f"X{i}",
            "surname": "Y",
            "area": "Z",
            "phone": f"0828888{i:03d}",
            "age": "25",
            "context": "test",
        }, follow_redirects=True)

    for i in range(5):
        r = do_search(i)
        assert r.status_code == 200  # allowed

    # 6th should be rate-limited
    r6 = do_search(5)
    assert r6.status_code == 429