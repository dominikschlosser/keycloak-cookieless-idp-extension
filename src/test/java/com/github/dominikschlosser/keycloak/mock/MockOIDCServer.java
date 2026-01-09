package com.github.dominikschlosser.keycloak.mock;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;

/**
 * A minimal mock OIDC Identity Provider for testing purposes. Implements just enough of the OIDC
 * protocol to test Keycloak's IDP broker flow.
 */
public class MockOIDCServer implements AutoCloseable {

    private final HttpServer server;
    private final int port;
    private final String issuer;

    private String lastReceivedState;
    private String lastReceivedRedirectUri;

    public MockOIDCServer(int port) throws IOException {
        this.port = port;
        this.issuer = "http://localhost:" + port;
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.setExecutor(Executors.newFixedThreadPool(2));

        setupEndpoints();
    }

    private void setupEndpoints() {
        // Well-known OpenID configuration
        server.createContext("/.well-known/openid-configuration", this::handleOpenIdConfiguration);

        // Authorization endpoint
        server.createContext("/authorize", this::handleAuthorize);

        // Token endpoint
        server.createContext("/token", this::handleToken);

        // JWKS endpoint
        server.createContext("/jwks", this::handleJwks);

        // UserInfo endpoint
        server.createContext("/userinfo", this::handleUserInfo);
    }

    private void handleOpenIdConfiguration(HttpExchange exchange) throws IOException {
        String config =
                """
            {
                "issuer": "%s",
                "authorization_endpoint": "%s/authorize",
                "token_endpoint": "%s/token",
                "userinfo_endpoint": "%s/userinfo",
                "jwks_uri": "%s/jwks",
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256", "none"],
                "scopes_supported": ["openid", "profile", "email"],
                "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
                "claims_supported": ["sub", "name", "email", "preferred_username"]
            }
            """
                        .formatted(issuer, issuer, issuer, issuer, issuer);

        sendJsonResponse(exchange, 200, config);
    }

    private void handleAuthorize(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());

        lastReceivedState = params.get("state");
        lastReceivedRedirectUri = params.get("redirect_uri");

        // Generate an authorization code
        String code = UUID.randomUUID().toString();

        // Build the redirect URL with code and state
        String redirectUrl = lastReceivedRedirectUri
                + "?code="
                + URLEncoder.encode(code, StandardCharsets.UTF_8)
                + "&state="
                + URLEncoder.encode(lastReceivedState, StandardCharsets.UTF_8);

        // Send redirect
        exchange.getResponseHeaders().set("Location", redirectUrl);
        exchange.sendResponseHeaders(302, -1);
        exchange.close();
    }

    private void handleToken(HttpExchange exchange) throws IOException {
        // Read and parse request body
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = parseFormParams(body);

        // Create a simple unsigned ID token (for testing only)
        String idToken = createMockIdToken();

        String tokenResponse =
                """
            {
                "access_token": "%s",
                "token_type": "Bearer",
                "expires_in": 3600,
                "id_token": "%s"
            }
            """
                        .formatted(UUID.randomUUID().toString(), idToken);

        sendJsonResponse(exchange, 200, tokenResponse);
    }

    private void handleJwks(HttpExchange exchange) throws IOException {
        // Empty JWKS - we use unsigned tokens for testing
        String jwks = """
            {
                "keys": []
            }
            """;
        sendJsonResponse(exchange, 200, jwks);
    }

    private void handleUserInfo(HttpExchange exchange) throws IOException {
        String userInfo =
                """
            {
                "sub": "mock-user-123",
                "name": "Mock User",
                "email": "mock@example.com",
                "preferred_username": "mockuser"
            }
            """;
        sendJsonResponse(exchange, 200, userInfo);
    }

    private String createMockIdToken() {
        // Create an unsigned JWT (alg: none) for testing
        String header = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));

        long now = Instant.now().getEpochSecond();
        String payload =
                """
            {
                "iss": "%s",
                "sub": "mock-user-123",
                "aud": "mock-client",
                "exp": %d,
                "iat": %d,
                "name": "Mock User",
                "email": "mock@example.com",
                "preferred_username": "mockuser"
            }
            """
                        .formatted(issuer, now + 3600, now);

        String encodedPayload =
                Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));

        // Unsigned token (alg: none) - signature part is empty
        return header + "." + encodedPayload + ".";
    }

    private void sendJsonResponse(HttpExchange exchange, int statusCode, String json) throws IOException {
        byte[] response = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(statusCode, response.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    private Map<String, String> parseQueryParams(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }
        for (String param : query.split("&")) {
            String[] keyValue = param.split("=", 2);
            if (keyValue.length == 2) {
                params.put(
                        URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8),
                        URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8));
            }
        }
        return params;
    }

    private Map<String, String> parseFormParams(String body) {
        return parseQueryParams(body);
    }

    public void start() {
        server.start();
    }

    @Override
    public void close() {
        server.stop(0);
    }

    public int getPort() {
        return port;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getLastReceivedState() {
        return lastReceivedState;
    }

    public String getLastReceivedRedirectUri() {
        return lastReceivedRedirectUri;
    }
}
