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


def test_login_success(client: TestClient, normal_user):
    """
    Test the happy path for user login:
    1. User exists in DB (via 'normal_user' fixture).
    2. Request with correct credentials.
    3. Expect 200 OK.
    4. Expect Access Token in JSON body.
    5. Expect Refresh Token in Cookies.
    """
    # OAuth2PasswordRequestForm expects 'username' field, even if it's an email
    login_data = {
        "username": "test@example.com", 
        "password": "password123"
    }
    
    response = client.post("/api/v1/auth/login", data=login_data)
    

    assert response.status_code == 200, f"Login failed: {response.text}"
    

    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    

    assert "refresh_token" in response.cookies
    assert response.cookies["refresh_token"] is not None

def test_refresh_token(client: TestClient, normal_user):
    """
    Test the token refresh flow:
    1. Login to get a valid refresh token cookie.
    2. Call /refresh endpoint.
    3. Expect a new access token.
    """
    # Step 1: Login to get the cookie
    login_data = {"username": "test@example.com", "password": "password123"}
    login_res = client.post("/api/v1/auth/login", data=login_data)
    refresh_cookie = login_res.cookies.get("refresh_token")
    
    assert refresh_cookie is not None

    # Step 2: Call /refresh
    # Note: TestClient handles cookies automatically if we reuse the client instance,
    # but we can also explicitly set it to be sure.
    client.cookies.set("refresh_token", refresh_cookie)
    response = client.post("/api/v1/auth/refresh")

    # Step 3: Verify response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_logout(client: TestClient, normal_user_token_headers, mock_redis):
    """
    Test the logout flow:
    1. Call /logout with a valid access token.
    2. Expect cookie to be cleared.
    3. Expect Redis to be called (to blacklist the token).
    """
    # Step 1: Logout
    client.cookies.set("refresh_token", "dummy_refresh_token_for_test")
    response = client.post(
        "/api/v1/auth/logout", 
        headers=normal_user_token_headers
    )
    
    assert response.status_code == 200
    
    # Step 2: Check Cookie Cleared (Should be empty or expired)
    # Different test clients handle 'delete_cookie' differently, 
    # but usually it sets the value to empty string or expires it.
    assert response.cookies.get("refresh_token") is None

    # Step 3: Verify Redis Interaction (Blacklist)
    # We verify that 'setex' was called on the mock object.
    # This ensures our Service Layer actually tried to blacklist the token.
    assert mock_redis.setex.called
    assert mock_redis.setex.call_count >= 1


def test_rbac_admin_access(client: TestClient, normal_user_token_headers, admin_user_token_headers):
    """
    Test Role-Based Access Control:
    1. Normal User -> GET /admin/users -> 403 Forbidden
    2. Admin User  -> GET /admin/users -> 200 OK (assuming endpoint exists)
    """
    
    # Scenario A: Normal User tries to access Admin API
    res_normal = client.get(
        "/api/v1/admin/users", 
        headers=normal_user_token_headers
    )

    assert res_normal.status_code == 403, "Normal user should be forbidden"

    # Scenario B: Admin User tries to access Admin API
    res_admin = client.get(
        "/api/v1/admin/users", 
        headers=admin_user_token_headers
    )
    # Admin should pass. 
    # Note: If you haven't implemented the logic inside /admin/users yet, 
    # this might return 200 or an empty list. Just ensure it's NOT 403/401.
    assert res_admin.status_code == 200, "Admin user should be allowed"