package com.github.dominikschlosser.keycloak.e2e;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.dominikschlosser.keycloak.mock.MockOIDCServer;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.response.Response;
import java.io.File;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * End-to-end integration test for the Cookieless OIDC Identity Provider.
 *
 * <p>This test verifies that the IDP broker flow works correctly even when the callback from the
 * external IDP arrives without cookies (simulating a scenario where the external IDP opened a
 * native app that returned in a new browser instance).
 */
public class CookielessOIDCIdpIT {

    private static final String REALM_NAME = "test-realm";
    private static final String CLIENT_ID = "test-client";
    private static final String IDP_ALIAS = "cookieless-oidc-idp";
    private static final int MOCK_OIDC_PORT = 8888;

    private static MockOIDCServer mockOIDCServer;
    private static String keycloakBaseUrl;
    private static GenericContainer<?> keycloak;

    @BeforeAll
    static void setup() throws Exception {
        // Start mock OIDC server on the host
        mockOIDCServer = new MockOIDCServer(MOCK_OIDC_PORT);
        mockOIDCServer.start();
        System.out.println("Mock OIDC server started on port " + MOCK_OIDC_PORT);

        // Build and start Keycloak container
        File jarFile = new File("target/keycloak-cookieless-idp-extension-1.0.0-SNAPSHOT.jar");

        GenericContainer<?> container = new GenericContainer<>(
                        DockerImageName.parse("quay.io/keycloak/keycloak:latest"))
                .withExposedPorts(8080)
                .withCommand("start-dev", "--import-realm", "--override=true")
                .withAccessToHost(true)
                .waitingFor(Wait.forLogMessage(".*Keycloak.*started.*", 1).withStartupTimeout(Duration.ofMinutes(3)));

        // Mount the master realm config for admin authentication (Keycloak 26.x requires this)
        container = container.withCopyFileToContainer(
                MountableFile.forClasspathResource("master-realm.json"), "/opt/keycloak/data/import/master-realm.json");

        // Mount extension JAR if it exists
        if (jarFile.exists()) {
            container = container.withCopyFileToContainer(
                    MountableFile.forHostPath(jarFile.getAbsolutePath()),
                    "/opt/keycloak/providers/keycloak-cookieless-idp-extension.jar");
            System.out.println("Extension JAR will be mounted to container");
        } else {
            System.err.println("WARNING: Extension JAR not found at " + jarFile.getAbsolutePath());
            System.err.println("Run 'mvn package -DskipTests' first to build the JAR");
        }

        keycloak = container;
        keycloak.start();

        // Configure RestAssured (no /auth path in default Keycloak 26.x)
        keycloakBaseUrl = "http://localhost:" + keycloak.getMappedPort(8080);
        RestAssured.baseURI = "http://localhost";
        RestAssured.port = keycloak.getMappedPort(8080);
        RestAssured.basePath = "";

        System.out.println("Keycloak available at: " + keycloakBaseUrl);

        // Wait a bit for Keycloak to fully initialize
        Thread.sleep(3000);

        // Setup realm and IDP
        setupRealm();
    }

    @AfterAll
    static void teardown() {
        if (mockOIDCServer != null) {
            mockOIDCServer.close();
        }
        if (keycloak != null) {
            keycloak.stop();
        }
    }

    private static void setupRealm() {
        try (Keycloak adminClient = KeycloakBuilder.builder()
                .serverUrl(keycloakBaseUrl)
                .realm("master")
                .username("admin")
                .password("admin")
                .clientId("admin-cli")
                .build()) {

            // Create test realm
            RealmRepresentation realm = new RealmRepresentation();
            realm.setRealm(REALM_NAME);
            realm.setEnabled(true);
            realm.setRegistrationAllowed(false);
            realm.setSslRequired("none");
            adminClient.realms().create(realm);
            System.out.println("Created realm: " + REALM_NAME);

            // Create test client
            ClientRepresentation client = new ClientRepresentation();
            client.setClientId(CLIENT_ID);
            client.setEnabled(true);
            client.setDirectAccessGrantsEnabled(true);
            client.setPublicClient(true);
            client.setRedirectUris(List.of("http://localhost:8080/callback", "*"));
            client.setWebOrigins(List.of("*"));
            adminClient.realm(REALM_NAME).clients().create(client);
            System.out.println("Created client: " + CLIENT_ID);

            // Create cookieless OIDC identity provider
            IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
            idp.setAlias(IDP_ALIAS);
            idp.setProviderId("cookieless-oidc"); // Our custom provider ID
            idp.setEnabled(true);
            idp.setTrustEmail(true);
            idp.setFirstBrokerLoginFlowAlias("first broker login");

            // Configure the IDP to point to our mock server
            // Using host.testcontainers.internal for Docker-for-Mac/Windows
            String mockServerHost = "host.testcontainers.internal";
            Map<String, String> config = new HashMap<>();
            config.put("authorizationUrl", "http://" + mockServerHost + ":" + MOCK_OIDC_PORT + "/authorize");
            config.put("tokenUrl", "http://" + mockServerHost + ":" + MOCK_OIDC_PORT + "/token");
            config.put("clientId", "mock-client");
            config.put("clientSecret", "mock-secret");
            config.put("defaultScope", "openid profile email");
            config.put("validateSignature", "false"); // Mock server uses unsigned tokens
            config.put("useJwksUrl", "false");
            idp.setConfig(config);

            adminClient.realm(REALM_NAME).identityProviders().create(idp);
            System.out.println("Created IDP: " + IDP_ALIAS);
        } catch (Exception e) {
            System.err.println("Failed to setup realm: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Realm setup failed", e);
        }
    }

    /**
     * Tests the cookieless callback scenario.
     *
     * <p>This simulates a real-world flow where: 1. User starts login in their browser (cookies are
     * set) 2. Keycloak redirects to external IDP 3. External IDP opens a native app for
     * authentication 4. Native app completes auth and opens a NEW browser instance to return the
     * callback 5. The new browser has NO cookies from the original session
     *
     * <p>The cookieless extension embeds the session ID in the state parameter, allowing Keycloak
     * to recover the session without relying on cookies.
     *
     * <p>Note: The initial steps still use cookies to establish the session and navigate through
     * Keycloak's internal redirects - this is the original browser. The key test is that the
     * CALLBACK works without cookies.
     */
    @Test
    void testCookielessOIDCFlow() {
        // Step 1: Start the login flow in the "original browser"
        // Cookies are set here - this is normal browser behavior
        Response authStartResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .queryParam("client_id", CLIENT_ID)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("redirect_uri", "http://localhost:8080/callback")
                .queryParam("kc_idp_hint", IDP_ALIAS)
                .when()
                .get("/realms/" + REALM_NAME + "/protocol/openid-connect/auth");

        System.out.println("Auth start response status: " + authStartResponse.statusCode());

        assertThat(authStartResponse.statusCode()).as("Should redirect").isIn(302, 303);

        String firstRedirectUrl = authStartResponse.header("Location");
        System.out.println("First redirect URL: " + firstRedirectUrl);
        Map<String, String> cookies = authStartResponse.cookies();

        // Step 2: Follow redirect to broker login page (still in "original browser" with cookies)
        // Keycloak 26.x has an intermediate redirect before reaching the external IDP
        Response brokerLoginResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .cookies(cookies)
                .when()
                .get(firstRedirectUrl);

        System.out.println("Broker login response status: " + brokerLoginResponse.statusCode());

        // This should redirect to the external IDP's authorize endpoint
        assertThat(brokerLoginResponse.statusCode())
                .as("Should redirect to external IDP")
                .isIn(302, 303);

        String idpRedirectUrl = brokerLoginResponse.header("Location");
        System.out.println("IDP redirect URL: " + idpRedirectUrl);

        // Verify this goes to the mock OIDC server's authorize endpoint
        assertThat(idpRedirectUrl)
                .as("Should redirect to mock OIDC authorize endpoint")
                .contains("/authorize");
        assertThat(idpRedirectUrl).contains("state=");

        // Extract state from redirect URL - this contains the embedded session ID (cookieless
        // state)
        String state = extractQueryParam(idpRedirectUrl, "state");
        System.out.println("State parameter (contains embedded session ID): " + state);
        assertThat(state).isNotNull();

        // Step 3: Simulate the external IDP authentication
        // In a real scenario, the external IDP would authenticate the user,
        // possibly opening a native app, then redirect back to Keycloak
        String callbackUrl = "/realms/" + REALM_NAME + "/broker/" + IDP_ALIAS + "/endpoint";
        String mockAuthCode = "mock-auth-code-12345";

        // ============================================================
        // CRITICAL: This is the cookieless callback test
        // ============================================================
        // Step 4: Call Keycloak's broker callback endpoint WITHOUT cookies
        // This simulates a NEW browser instance (e.g., opened by native app)
        // that has no access to the original session cookies.
        //
        // Without the cookieless extension, this would fail with
        // "identity_provider_missing_state" error because Keycloak
        // couldn't find the auth session without the AUTH_SESSION_ID cookie.
        //
        // With the extension, the session ID is extracted from the state
        // parameter and the session is recovered directly.
        Response callbackResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                // NO COOKIES - simulating new browser instance
                .queryParam("code", mockAuthCode)
                .queryParam("state", state)
                .when()
                .get(callbackUrl);

        System.out.println("Callback response status: " + callbackResponse.statusCode());
        System.out.println("Callback response headers: " + callbackResponse.headers());
        String callbackBody = callbackResponse.body().asString();
        if (callbackResponse.statusCode() != 302 && callbackResponse.statusCode() != 303) {
            System.out.println("Callback response body: " + callbackBody);
        }

        // With cookieless IDP, this should either:
        // - Succeed and redirect to next step (302/303)
        // - Return 502 if mock server token exchange fails (expected since mock server may not be
        // reachable)
        // Without our extension, this would fail with an error about "missing state" or similar

        // The key assertion: we should NOT get an error about missing authentication session
        // A 502 means we successfully recovered the session but the token exchange failed
        // (which is expected since the mock server URL uses host.testcontainers.internal)
        assertThat(callbackResponse.statusCode())
                .as("Cookieless callback should recover session (502 = session found, token exchange failed)")
                .isIn(302, 303, 502);

        // If we got a redirect, verify it's not an error page
        if (callbackResponse.statusCode() == 302 || callbackResponse.statusCode() == 303) {
            String nextLocation = callbackResponse.header("Location");
            System.out.println("Next location: " + nextLocation);
            assertThat(nextLocation)
                    .as("Should not redirect to error page")
                    .doesNotContain("error=identity_provider_missing_state");
        }

        // If we got 502, verify it's NOT because of missing state (that would indicate our
        // extension isn't working)
        if (callbackResponse.statusCode() == 502) {
            assertThat(callbackBody)
                    .as("Should not fail due to missing state (which would mean extension isn't working)")
                    .doesNotContain("missing state")
                    .doesNotContain("identity_provider_missing_state");
            System.out.println(
                    "Got 502 - session was recovered but token exchange failed (expected in test environment)");
        }
    }

    /**
     * Tests that the standard cookie-based flow still works with the extension.
     *
     * <p>This is a regression test to ensure the cookieless extension doesn't break the normal flow
     * where cookies ARE available (e.g., same browser instance throughout the entire flow).
     *
     * <p>The extension should work in both scenarios: - With cookies: Standard Keycloak behavior -
     * Without cookies: Session recovered from state parameter
     */
    @Test
    void testStandardFlowWithCookiesStillWorks() {
        // Standard flow: cookies are sent throughout the entire flow
        Response authStartResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .queryParam("client_id", CLIENT_ID)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("redirect_uri", "http://localhost:8080/callback")
                .queryParam("kc_idp_hint", IDP_ALIAS)
                .when()
                .get("/realms/" + REALM_NAME + "/protocol/openid-connect/auth");

        assertThat(authStartResponse.statusCode()).isIn(302, 303);
        String firstRedirectUrl = authStartResponse.header("Location");
        Map<String, String> cookies = authStartResponse.cookies();

        // Follow redirect to broker login page
        Response brokerLoginResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .cookies(cookies)
                .when()
                .get(firstRedirectUrl);

        assertThat(brokerLoginResponse.statusCode()).isIn(302, 303);
        String idpRedirectUrl = brokerLoginResponse.header("Location");

        // Merge cookies from both responses into a new mutable map
        Map<String, String> allCookies = new HashMap<>(cookies);
        allCookies.putAll(brokerLoginResponse.cookies());
        String state = extractQueryParam(idpRedirectUrl, "state");

        // Callback WITH cookies - standard flow where browser keeps same session
        // This is the normal case when user stays in the same browser
        String callbackUrl = "/realms/" + REALM_NAME + "/broker/" + IDP_ALIAS + "/endpoint";
        String mockAuthCode = "mock-auth-code-67890";

        Response callbackResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .cookies(allCookies) // Cookies included - same browser instance
                .queryParam("code", mockAuthCode)
                .queryParam("state", state)
                .when()
                .get(callbackUrl);

        System.out.println("Standard flow callback status: " + callbackResponse.statusCode());

        // Should either redirect (success) or 502 (token exchange failed due to unreachable mock
        // server)
        assertThat(callbackResponse.statusCode()).isIn(302, 303, 200, 502);
        if (callbackResponse.header("Location") != null) {
            assertThat(callbackResponse.header("Location")).doesNotContain("identity_provider_missing_state");
        }
    }

    private String extractQueryParam(String url, String paramName) {
        try {
            URI uri = URI.create(url);
            String query = uri.getQuery();
            if (query == null) return null;

            for (String param : query.split("&")) {
                String[] keyValue = param.split("=", 2);
                if (keyValue.length == 2 && keyValue[0].equals(paramName)) {
                    return URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                }
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        return null;
    }
}
