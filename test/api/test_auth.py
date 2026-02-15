from fastapi.testclient import TestClient

def test_login_failure_wrong_credentials(client: TestClient):
    """
    Test that logging in with incorrect credentials returns 401 Unauthorized.
    """
    # Payload with wrong password
    login_data = {
        "username": "nonexistent@example.com",
        "password": "wrongpassword"
    }
    
    response = client.post("/api/v1/auth/login", data=login_data)
    
    # Assertions
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]

def test_admin_access_denied_without_token(client: TestClient):
    """
    Test that accessing a protected Admin endpoint without a token 
    returns 401 Unauthorized.
    """
    response = client.get("/api/v1/admin/users")
    
    # Assertions
    assert response.status_code == 401
    # Check if the detailed error message matches FastAPI's default or your custom one
    assert response.json()["detail"] == "Not authenticated"

def test_google_login_redirect(client: TestClient):
    """
    Test that the Google login endpoint correctly redirects to Google 
    and sets the necessary cookies (state, verifier).
    """
    response = client.get("/api/v1/auth/login/google", follow_redirects=False)
    
    # Assertions
    assert response.status_code == 307  # FastAPI RedirectResponse defaults to 307
    assert "accounts.google.com" in response.headers["location"]
    
    # Check if cookies are set
    assert "oauth_state" in response.cookies
    assert "oauth_verifier" in response.cookies