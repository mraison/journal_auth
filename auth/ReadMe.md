// Create new user with password:
curl -X POST "http://localhost:8081/user" -d "{\"username\": \"mraison\", \"password\":\"mypass\"}" -H "Content-Type: Application/json"

// Delete user:
curl -X DELETE "http://localhost:8081/user" -d "{\"username\": \"mraison\", \"password\":\"mypass\"}" -H "Content-Type: Application/json"

// Update password:
curl -X POST "http://localhost:8081/user" -d "{\"username\": \"mraison\", \"password\":\"mypass\", \"newPassword\": \"my new password\"}" -H "Content-Type: Application/json"

// Request a jwt for the new user:
curl -X POST "http://localhost:8081/request_jwt" -d "{\"username\": \"mraison\", \"password\":\"mypass\"}" -H "Content-Type: Application/json"

// Verify the jwt token works:
curl "http://localhost:8081/jwt_healthcheck" -H "Authorization: Bearer eyJhbGciOiAiSFMyNTYifQ==.eyJ1c2VybmFtZSI6ICJtcmFpc29uIiwgInJvbGUiOiAidXNlciJ9.YBuPLgUAE0t2Hk1ViDTbe1ZhvcA3AFoO4DiIZFn3+2Y="

