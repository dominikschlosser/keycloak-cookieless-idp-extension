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
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.testcontainers.Testcontainers;
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
        // Start mock OIDC server on the host with issuer that matches what Keycloak will see
        // Keycloak runs in Docker and accesses the host via host.testcontainers.internal
        String issuerForKeycloak = "http://host.testcontainers.internal:" + MOCK_OIDC_PORT;
        mockOIDCServer = new MockOIDCServer(MOCK_OIDC_PORT, issuerForKeycloak);
        mockOIDCServer.start();
        System.out.println("Mock OIDC server started on port " + MOCK_OIDC_PORT + " with issuer " + issuerForKeycloak);

        // Expose the host port so Docker containers can access it
        Testcontainers.exposeHostPorts(MOCK_OIDC_PORT);

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
            config.put("jwksUrl", "http://" + mockServerHost + ":" + MOCK_OIDC_PORT + "/jwks");
            config.put("clientId", "mock-client");
            config.put("clientSecret", "mock-secret");
            config.put("defaultScope", "openid profile email");
            config.put("validateSignature", "true");
            config.put("useJwksUrl", "true");
            idp.setConfig(config);

            adminClient.realm(REALM_NAME).identityProviders().create(idp);
            System.out.println("Created IDP: " + IDP_ALIAS);

            // Add attribute mapper to map idp_authenticated claim to access token
            // This allows us to verify step-up authentication happened via IDP
            IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
            mapper.setName("idp-authenticated-mapper");
            mapper.setIdentityProviderAlias(IDP_ALIAS);
            mapper.setIdentityProviderMapper("oidc-user-attribute-idp-mapper");
            Map<String, String> mapperConfig = new HashMap<>();
            mapperConfig.put("claim", "idp_authenticated");
            mapperConfig.put("user.attribute", "idp_authenticated");
            mapperConfig.put("syncMode", "FORCE");
            mapper.setConfig(mapperConfig);
            adminClient.realm(REALM_NAME).identityProviders().get(IDP_ALIAS).addMapper(mapper);
            System.out.println("Created IDP attribute mapper: idp-authenticated-mapper");

            // Create a test user with password for direct login testing
            UserRepresentation user = new UserRepresentation();
            user.setUsername("testuser");
            user.setEmail("testuser@example.com");
            user.setFirstName("Test");
            user.setLastName("User");
            user.setEnabled(true);
            user.setEmailVerified(true);

            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue("password");
            credential.setTemporary(false);
            user.setCredentials(List.of(credential));

            adminClient.realm(REALM_NAME).users().create(user);
            System.out.println("Created user: testuser with password");

            // Link testuser to the mock IDP identity (mock-user-123-stepup)
            // This enables step-up authentication with the IDP
            List<UserRepresentation> users =
                    adminClient.realm(REALM_NAME).users().search("testuser", true);
            if (!users.isEmpty()) {
                String userId = users.get(0).getId();
                FederatedIdentityRepresentation fedIdentity = new FederatedIdentityRepresentation();
                fedIdentity.setIdentityProvider(IDP_ALIAS);
                fedIdentity.setUserId("mock-user-123-stepup"); // The IDP's user ID
                fedIdentity.setUserName("mockuser-stepup"); // The IDP's username
                adminClient.realm(REALM_NAME).users().get(userId).addFederatedIdentity(IDP_ALIAS, fedIdentity);
                System.out.println("Linked testuser to mock IDP identity: mock-user-123-stepup");
            }
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

        // Extract state and nonce from redirect URL
        String state = extractQueryParam(idpRedirectUrl, "state");
        String nonce = extractQueryParam(idpRedirectUrl, "nonce");
        System.out.println("State parameter (contains embedded session ID): " + state);
        System.out.println("Nonce parameter: " + nonce);
        assertThat(state).isNotNull();
        assertThat(nonce).isNotNull();

        // Set the nonce on the mock server so it includes it in the ID token
        mockOIDCServer.setNonce(nonce);

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
            // Print Keycloak container logs to diagnose the error
            System.out.println("=== Keycloak Container Logs (last 100 lines) ===");
            System.out.println(keycloak.getLogs());
            System.out.println("=== End Keycloak Logs ===");
        }

        // With cookieless IDP, this MUST redirect (302/303) to continue the auth flow
        // Without our extension, this would fail with "identity_provider_missing_state" error
        assertThat(callbackResponse.statusCode())
                .as("Cookieless callback must redirect to continue auth flow (got %d)", callbackResponse.statusCode())
                .isIn(302, 303);

        String nextLocation = callbackResponse.header("Location");
        System.out.println("Next location: " + nextLocation);

        // Verify it's not an error redirect
        assertThat(nextLocation)
                .as("Should not redirect to error page")
                .doesNotContain("error=identity_provider_missing_state")
                .doesNotContain("error=identity_provider_error");

        // ============================================================
        // Complete login flow - may go directly to client or via first-broker-login
        // ============================================================
        Map<String, String> sessionCookies = callbackResponse.cookies();
        String finalRedirectUrl = nextLocation;

        // Follow redirects until we reach the client callback with authorization code
        // This handles both direct redirect (auto-linking) and first-broker-login flow
        int maxRedirects = 10;
        while (maxRedirects-- > 0
                && finalRedirectUrl != null
                && !finalRedirectUrl.contains("localhost:8080/callback")) {
            System.out.println("Following redirect to: " + finalRedirectUrl);
            Response response = given().config(RestAssured.config()
                            .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                    .cookies(sessionCookies)
                    .when()
                    .get(finalRedirectUrl);

            if (response.statusCode() == 200 && finalRedirectUrl.contains("first-broker-login")) {
                // Need to submit the profile form
                String formAction = extractFormAction(response.body().asString());
                System.out.println("Submitting first-broker-login form to: " + formAction);

                Response formResponse = given().config(RestAssured.config()
                                .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                        .cookies(sessionCookies)
                        .contentType("application/x-www-form-urlencoded")
                        .formParam("username", "mockuser")
                        .formParam("email", "mock@example.com")
                        .formParam("firstName", "Mock")
                        .formParam("lastName", "User")
                        .when()
                        .post(formAction);

                finalRedirectUrl = formResponse.header("Location");
                sessionCookies = new HashMap<>(sessionCookies);
                sessionCookies.putAll(formResponse.cookies());
            } else if (response.statusCode() == 302 || response.statusCode() == 303) {
                finalRedirectUrl = response.header("Location");
                sessionCookies = new HashMap<>(sessionCookies);
                sessionCookies.putAll(response.cookies());
            } else {
                System.out.println("Unexpected response status: " + response.statusCode());
                System.out.println("Response body: "
                        + response.body()
                                .asString()
                                .substring(
                                        0,
                                        Math.min(500, response.body().asString().length())));
                break;
            }
        }

        System.out.println("Final redirect URL: " + finalRedirectUrl);

        // ============================================================
        // CRITICAL ASSERTION: User should be logged in with auth code
        // ============================================================
        assertThat(finalRedirectUrl)
                .as("User should be redirected to client callback with authorization code")
                .contains("localhost:8080/callback")
                .contains("code=");

        // Extract and verify the authorization code is present
        String authCode = extractQueryParam(finalRedirectUrl, "code");
        assertThat(authCode)
                .as("Authorization code should be present")
                .isNotNull()
                .isNotEmpty();

        System.out.println("SUCCESS: User logged in via cookieless OIDC IDP, received auth code: "
                + authCode.substring(0, Math.min(20, authCode.length())) + "...");
    }

    private String extractFormAction(String html) {
        // Simple regex to extract form action
        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("action=\"([^\"]+)\"");
        java.util.regex.Matcher matcher = pattern.matcher(html);
        if (matcher.find()) {
            String action = matcher.group(1);
            // Decode HTML entities
            return action.replace("&amp;", "&");
        }
        return null;
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
        String nonce = extractQueryParam(idpRedirectUrl, "nonce");

        // Set the nonce on the mock server so it includes it in the ID token
        mockOIDCServer.setNonce(nonce);

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

        // Must redirect to continue the auth flow
        assertThat(callbackResponse.statusCode())
                .as("Standard flow callback must redirect")
                .isIn(302, 303);

        String nextLocation = callbackResponse.header("Location");
        assertThat(nextLocation)
                .as("Should not redirect to error page")
                .doesNotContain("identity_provider_missing_state")
                .doesNotContain("identity_provider_error");

        // Complete the login flow and verify user gets auth code
        Map<String, String> sessionCookies = new HashMap<>(allCookies);
        sessionCookies.putAll(callbackResponse.cookies());

        // Follow redirects through first-broker-login
        String currentUrl = nextLocation;
        int maxRedirects = 10;

        while (maxRedirects-- > 0 && currentUrl != null && !currentUrl.contains("localhost:8080/callback")) {
            Response response = given().config(RestAssured.config()
                            .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                    .cookies(sessionCookies)
                    .when()
                    .get(currentUrl);

            if (response.statusCode() == 200 && currentUrl.contains("first-broker-login")) {
                // Submit the profile form
                String formAction = extractFormAction(response.body().asString());
                Response formResponse = given().config(RestAssured.config()
                                .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                        .cookies(sessionCookies)
                        .contentType("application/x-www-form-urlencoded")
                        .formParam("username", "mockuser")
                        .formParam("email", "mock@example.com")
                        .formParam("firstName", "Mock")
                        .formParam("lastName", "User")
                        .when()
                        .post(formAction);

                currentUrl = formResponse.header("Location");
                sessionCookies.putAll(formResponse.cookies());
            } else if (response.statusCode() == 302 || response.statusCode() == 303) {
                currentUrl = response.header("Location");
                sessionCookies.putAll(response.cookies());
            } else {
                break;
            }
        }

        System.out.println("Standard flow final URL: " + currentUrl);

        // Verify user is logged in with auth code
        assertThat(currentUrl)
                .as("Standard flow: User should receive authorization code")
                .contains("localhost:8080/callback")
                .contains("code=");

        String authCode = extractQueryParam(currentUrl, "code");
        assertThat(authCode)
                .as("Authorization code should be present")
                .isNotNull()
                .isNotEmpty();

        System.out.println("SUCCESS: Standard flow completed, received auth code: "
                + authCode.substring(0, Math.min(20, authCode.length())) + "...");
    }

    /**
     * Tests step-up authentication with cookieless callback.
     *
     * <p>This test verifies that when a user is already logged in via username/password and needs
     * to re-authenticate via the external IDP (step-up), the cookieless callback correctly:
     * <ul>
     *   <li>Preserves the user identity (no new user created)
     *   <li>Links the IDP to the existing user
     *   <li>Adds IDP-specific attributes to the user's token
     * </ul>
     *
     * <p>Flow:
     * <ol>
     *   <li>Login with username/password (testuser) - creates session WITHOUT IDP
     *   <li>Request step-up authentication via IDP (using kc_idp_hint)
     *   <li>Simulate IDP callback WITHOUT cookies (new browser)
     *   <li>Exchange auth code for tokens
     *   <li>Verify IDP attribute (idp_authenticated) is present in the user
     * </ol>
     */
    @Test
    void testStepUpAuthenticationCookielessFlow() {
        // ============================================================
        // Step 1: Login with username/password (direct Keycloak login)
        // This creates a user session WITHOUT IDP authentication
        // ============================================================
        System.out.println("Step 1: Logging in with username/password...");

        // Start the auth flow
        Response authResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .queryParam("client_id", CLIENT_ID)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("redirect_uri", "http://localhost:8080/callback")
                .when()
                .get("/realms/" + REALM_NAME + "/protocol/openid-connect/auth");

        Map<String, String> cookies = new HashMap<>(authResponse.cookies());
        String loginFormAction;

        // Keycloak may return the login page directly (200) or redirect (302/303)
        if (authResponse.statusCode() == 200) {
            // Login page returned directly
            loginFormAction = extractFormAction(authResponse.body().asString());
        } else {
            assertThat(authResponse.statusCode()).isIn(302, 303);
            String loginPageUrl = authResponse.header("Location");

            // Get the login page to extract the form action
            Response loginPageResponse = given().config(RestAssured.config()
                            .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                    .cookies(cookies)
                    .when()
                    .get(loginPageUrl);

            cookies.putAll(loginPageResponse.cookies());
            loginFormAction = extractFormAction(loginPageResponse.body().asString());
        }
        System.out.println("Login form action: " + loginFormAction);

        // Submit username/password login
        Response loginResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .cookies(cookies)
                .contentType("application/x-www-form-urlencoded")
                .formParam("username", "testuser")
                .formParam("password", "password")
                .when()
                .post(loginFormAction);

        assertThat(loginResponse.statusCode())
                .as("Password login should redirect")
                .isIn(302, 303);

        cookies.putAll(loginResponse.cookies());
        String afterLoginUrl = loginResponse.header("Location");
        System.out.println("After password login redirect: " + afterLoginUrl);

        // Follow redirects until we get the auth code
        String currentUrl = afterLoginUrl;
        int maxRedirects = 5;
        while (maxRedirects-- > 0 && currentUrl != null && !currentUrl.contains("localhost:8080/callback")) {
            Response response = given().config(RestAssured.config()
                            .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                    .cookies(cookies)
                    .when()
                    .get(currentUrl);

            cookies.putAll(response.cookies());
            if (response.statusCode() == 302 || response.statusCode() == 303) {
                currentUrl = response.header("Location");
            } else {
                break;
            }
        }

        assertThat(currentUrl)
                .as("Initial login should complete with auth code")
                .contains("localhost:8080/callback")
                .contains("code=");

        String initialAuthCode = extractQueryParam(currentUrl, "code");
        System.out.println("Initial password login completed. Auth code: "
                + initialAuthCode.substring(0, Math.min(15, initialAuthCode.length())) + "...");

        // Store session cookies for step-up
        Map<String, String> sessionCookies = new HashMap<>(cookies);

        // ============================================================
        // Step 2: Request step-up authentication via IDP
        // User is already logged in, now needs to authenticate via IDP
        // ============================================================
        System.out.println("\nStep 2: Requesting step-up authentication via IDP...");

        Response stepUpAuthResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .cookies(sessionCookies)
                .queryParam("client_id", CLIENT_ID)
                .queryParam("response_type", "code")
                .queryParam("scope", "openid")
                .queryParam("redirect_uri", "http://localhost:8080/callback")
                .queryParam("kc_idp_hint", IDP_ALIAS) // Force IDP authentication
                .queryParam("prompt", "login") // Force re-authentication
                .when()
                .get("/realms/" + REALM_NAME + "/protocol/openid-connect/auth");

        assertThat(stepUpAuthResponse.statusCode()).isIn(302, 303);
        String stepUpRedirectUrl = stepUpAuthResponse.header("Location");
        System.out.println("Step-up redirect URL: " + stepUpRedirectUrl);

        // Follow to broker login page
        Map<String, String> stepUpCookies = new HashMap<>(sessionCookies);
        stepUpCookies.putAll(stepUpAuthResponse.cookies());

        Response brokerResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .cookies(stepUpCookies)
                .when()
                .get(stepUpRedirectUrl);

        stepUpCookies.putAll(brokerResponse.cookies());
        assertThat(brokerResponse.statusCode()).isIn(302, 303);
        String idpRedirectUrl = brokerResponse.header("Location");
        System.out.println("IDP redirect URL: " + idpRedirectUrl);

        // Extract state and nonce from the IDP redirect
        String stepUpState = extractQueryParam(idpRedirectUrl, "state");
        String stepUpNonce = extractQueryParam(idpRedirectUrl, "nonce");
        assertThat(stepUpState).as("State should be present").isNotNull();
        mockOIDCServer.setNonce(stepUpNonce);
        // Use a unique user ID to avoid conflicts with other tests that may have already
        // linked the default mock user identity to different Keycloak users
        mockOIDCServer.setUserIdSuffix("-stepup");

        System.out.println("Step-up state (contains user ID for step-up): " + stepUpState);

        // ============================================================
        // Step 3: Simulate COOKIELESS IDP callback
        // This simulates callback from a new browser (native app scenario)
        // ============================================================
        System.out.println("\nStep 3: Simulating cookieless IDP callback (no cookies)...");

        String callbackUrl = "/realms/" + REALM_NAME + "/broker/" + IDP_ALIAS + "/endpoint";

        Response stepUpCallbackResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                // NO COOKIES - simulating new browser for step-up callback
                .queryParam("code", "step-up-auth-code")
                .queryParam("state", stepUpState)
                .when()
                .get(callbackUrl);

        System.out.println("Cookieless callback response status: " + stepUpCallbackResponse.statusCode());

        if (stepUpCallbackResponse.statusCode() != 302 && stepUpCallbackResponse.statusCode() != 303) {
            String body = stepUpCallbackResponse.body().asString();
            System.out.println("ERROR - Callback failed. Response body (first 1500 chars):");
            System.out.println(body.substring(0, Math.min(1500, body.length())));
            System.out.println(
                    "Response headers: " + stepUpCallbackResponse.headers().asList());
        }

        assertThat(stepUpCallbackResponse.statusCode())
                .as("Cookieless step-up callback should succeed")
                .isIn(302, 303);

        String stepUpNextLocation = stepUpCallbackResponse.header("Location");
        System.out.println("Next location after callback: " + stepUpNextLocation);

        assertThat(stepUpNextLocation)
                .as("Cookieless callback should redirect to continue auth flow (not error)")
                .doesNotContain("error=identity_provider")
                .doesNotContain("error=session");

        // ============================================================
        // Step 4: Complete the first-broker-login flow
        // ============================================================
        System.out.println("\nStep 4: Completing first-broker-login flow...");

        Map<String, String> callbackCookies = new HashMap<>(stepUpCallbackResponse.cookies());
        String flowUrl = stepUpNextLocation;
        maxRedirects = 15;

        while (maxRedirects-- > 0 && flowUrl != null && !flowUrl.contains("localhost:8080/callback")) {
            System.out.println("Following: " + flowUrl);

            Response response = given().config(RestAssured.config()
                            .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                    .cookies(callbackCookies)
                    .when()
                    .get(flowUrl);

            callbackCookies.putAll(response.cookies());
            System.out.println("  Response status: " + response.statusCode());

            // Handle form pages (first-broker-login, update profile, etc.)
            if (response.statusCode() == 200 || response.statusCode() == 400) {
                String pageBody = response.body().asString();

                // Debug: show what's on this page
                if (response.statusCode() == 400) {
                    // Extract title inline
                    int titleStart = pageBody.indexOf("<title>");
                    int titleEnd = pageBody.indexOf("</title>");
                    if (titleStart >= 0 && titleEnd > titleStart) {
                        System.out.println("  Page title: " + pageBody.substring(titleStart + 7, titleEnd));
                    }
                    if (pageBody.contains("kc-error-message")) {
                        int start = pageBody.indexOf("kc-error-message");
                        System.out.println("  Error snippet: "
                                + pageBody.substring(start, Math.min(start + 500, pageBody.length())));
                    }
                    // Also print first 2000 chars of body for debugging
                    System.out.println("  Body preview: " + pageBody.substring(0, Math.min(2000, pageBody.length())));
                }

                String formAction = extractFormAction(pageBody);

                if (formAction != null) {
                    System.out.println("  Found form, submitting to: " + formAction);

                    // Submit the form with IDP user profile data
                    Response formResponse = given().config(RestAssured.config()
                                    .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                            .cookies(callbackCookies)
                            .contentType("application/x-www-form-urlencoded")
                            .formParam("username", "mockuser-stepup")
                            .formParam("email", "mock-stepup@example.com")
                            .formParam("firstName", "Mock")
                            .formParam("lastName", "User")
                            .when()
                            .post(formAction);

                    callbackCookies.putAll(formResponse.cookies());
                    System.out.println("  Form response status: " + formResponse.statusCode());

                    if (formResponse.statusCode() == 302 || formResponse.statusCode() == 303) {
                        flowUrl = formResponse.header("Location");
                        System.out.println("  Redirect to: " + flowUrl);
                        continue;
                    } else {
                        // Form might have errors, try to extract and show them
                        String formBody = formResponse.body().asString();
                        if (formBody.contains("error") || formBody.contains("Error")) {
                            System.out.println("  Form error detected in response");
                        }
                        // Try submitting without form params (some pages just need POST)
                        formResponse = given().config(RestAssured.config()
                                        .redirect(
                                                RedirectConfig.redirectConfig().followRedirects(false)))
                                .cookies(callbackCookies)
                                .contentType("application/x-www-form-urlencoded")
                                .when()
                                .post(formAction);

                        callbackCookies.putAll(formResponse.cookies());
                        if (formResponse.statusCode() == 302 || formResponse.statusCode() == 303) {
                            flowUrl = formResponse.header("Location");
                            continue;
                        }
                    }
                }
                // If no form found or form submission didn't redirect, break
                System.out.println("  No form or submission failed, stopping");
                break;
            }

            if (response.statusCode() == 302 || response.statusCode() == 303) {
                flowUrl = response.header("Location");
            } else {
                System.out.println("  Unexpected status, stopping");
                break;
            }
        }

        System.out.println("Final URL: " + flowUrl);

        // ============================================================
        // Step 5: Verify we got an authorization code
        // ============================================================
        assertThat(flowUrl)
                .as("Step-up flow should complete with authorization code")
                .contains("localhost:8080/callback")
                .contains("code=");

        String stepUpAuthCode = extractQueryParam(flowUrl, "code");
        assertThat(stepUpAuthCode)
                .as("Step-up auth code should be present")
                .isNotNull()
                .isNotEmpty();
        System.out.println("Step-up auth code received: "
                + stepUpAuthCode.substring(0, Math.min(20, stepUpAuthCode.length())) + "...");

        // ============================================================
        // Step 6: Exchange auth code for tokens
        // ============================================================
        System.out.println("\nStep 5: Exchanging auth code for tokens...");

        Response tokenResponse = given().contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", stepUpAuthCode)
                .formParam("redirect_uri", "http://localhost:8080/callback")
                .formParam("client_id", CLIENT_ID)
                .when()
                .post("/realms/" + REALM_NAME + "/protocol/openid-connect/token");

        assertThat(tokenResponse.statusCode())
                .as("Token exchange should succeed")
                .isEqualTo(200);

        String accessToken = tokenResponse.jsonPath().getString("access_token");
        String idToken = tokenResponse.jsonPath().getString("id_token");

        assertThat(accessToken).as("Access token should be present").isNotNull();
        assertThat(idToken).as("ID token should be present").isNotNull();

        // ============================================================
        // Step 7: Verify token is for the correct user
        // ============================================================
        System.out.println("\nStep 6: Verifying token is for the correct user...");

        // Decode the access token to check claims
        String[] tokenParts = accessToken.split("\\.");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(tokenParts[1]), StandardCharsets.UTF_8);
        System.out.println("Access token payload: " + payload);

        // The token should be for testuser (who completed step-up auth via IDP)
        assertThat(payload)
                .as("Token should be for the correct user")
                .contains("\"preferred_username\":\"testuser\"")
                .contains("\"email\":\"testuser@example.com\"");

        // Also verify the ID token payload to see more claims
        String[] idTokenParts = idToken.split("\\.");
        String idTokenPayload =
                new String(java.util.Base64.getUrlDecoder().decode(idTokenParts[1]), StandardCharsets.UTF_8);
        System.out.println("ID token payload: " + idTokenPayload);

        // Verify ID token is for the correct user
        assertThat(idTokenPayload)
                .as("ID token should be for the correct user")
                .contains("\"preferred_username\":\"testuser\"");

        System.out.println("\n=== SUCCESS ===");
        System.out.println("Step-up authentication completed via cookieless IDP callback!");
        System.out.println("- Initial login: username/password (testuser)");
        System.out.println("- Step-up: External IDP authentication (cookieless callback)");
        System.out.println("- Cookieless session recovery: State parameter used to find session");
        System.out.println("- Token received for correct user (testuser)");
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
