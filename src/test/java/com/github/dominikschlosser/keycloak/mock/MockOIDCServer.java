package com.github.dominikschlosser.keycloak.mock;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
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
    private final KeyPair keyPair;
    private final String keyId;

    private String lastReceivedState;
    private String lastReceivedRedirectUri;
    private String lastReceivedNonce;

    public MockOIDCServer(int port) throws IOException {
        this(port, "http://localhost:" + port);
    }

    public MockOIDCServer(int port, String issuer) throws IOException {
        this.port = port;
        this.issuer = issuer;
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.setExecutor(Executors.newFixedThreadPool(2));
        this.keyPair = generateKeyPair();
        this.keyId = "test-key-1";

        setupEndpoints();
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
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
        System.out.println("Mock OIDC Server: Received authorize request: " + exchange.getRequestURI());
        Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());

        lastReceivedState = params.get("state");
        lastReceivedRedirectUri = params.get("redirect_uri");
        lastReceivedNonce = params.get("nonce");

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
        System.out.println("Mock OIDC Server: Received token request");
        // Read and parse request body
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        System.out.println("Mock OIDC Server: Token request body: " + body);
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

        System.out.println("Mock OIDC Server: Sending token response with ID token");
        System.out.println("Mock OIDC Server: ID token (first 200 chars): " + idToken.substring(0, Math.min(200, idToken.length())));
        sendJsonResponse(exchange, 200, tokenResponse);
    }

    private void handleJwks(HttpExchange exchange) throws IOException {
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        String n = Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsignedByteArray(publicKey.getModulus()));
        String e = Base64.getUrlEncoder().withoutPadding().encodeToString(toUnsignedByteArray(publicKey.getPublicExponent()));

        String jwks = """
            {
                "keys": [{
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "%s",
                    "alg": "RS256",
                    "n": "%s",
                    "e": "%s"
                }]
            }
            """.formatted(keyId, n, e);
        sendJsonResponse(exchange, 200, jwks);
    }

    private byte[] toUnsignedByteArray(BigInteger bigInt) {
        byte[] bytes = bigInt.toByteArray();
        // Remove leading zero byte if present (used for sign in Java's BigInteger)
        if (bytes[0] == 0 && bytes.length > 1) {
            byte[] tmp = new byte[bytes.length - 1];
            System.arraycopy(bytes, 1, tmp, 0, tmp.length);
            return tmp;
        }
        return bytes;
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
        try {
            // Create a signed JWT with RS256
            String header = Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"" + keyId + "\"}").getBytes(StandardCharsets.UTF_8));

            long now = Instant.now().getEpochSecond();
            String nonceField = lastReceivedNonce != null ? ",\n                    \"nonce\": \"" + lastReceivedNonce + "\"" : "";
            String payloadJson =
                    """
                {
                    "iss": "%s",
                    "sub": "mock-user-123",
                    "aud": "mock-client",
                    "exp": %d,
                    "iat": %d,
                    "name": "Mock User",
                    "email": "mock@example.com",
                    "preferred_username": "mockuser"%s
                }
                """
                            .formatted(issuer, now + 3600, now, nonceField);

            String encodedPayload =
                    Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(StandardCharsets.UTF_8));

            // Sign the token
            String dataToSign = header + "." + encodedPayload;
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            signature.update(dataToSign.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = signature.sign();
            String encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

            return dataToSign + "." + encodedSignature;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create ID token", e);
        }
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

    /**
     * Sets the nonce that should be included in ID tokens.
     * Use this when the test bypasses the authorize endpoint.
     */
    public void setNonce(String nonce) {
        this.lastReceivedNonce = nonce;
    }
}
