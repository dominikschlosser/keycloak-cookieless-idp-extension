package com.github.dominikschlosser.keycloak.e2e;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.dominikschlosser.keycloak.mock.MockSAMLServer;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.response.Response;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.testcontainers.Testcontainers;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * End-to-end integration test for the Cookieless SAML Identity Provider.
 *
 * <p>This test verifies that the SAML IDP broker flow works correctly even when the callback from
 * the external IDP arrives without cookies (simulating a scenario where the external IDP opened a
 * native app that returned in a new browser instance).
 */
public class CookielessSAMLIdpIT {

    private static final String REALM_NAME = "test-realm";
    private static final String CLIENT_ID = "test-client";
    private static final String IDP_ALIAS = "cookieless-saml-idp";
    private static final int MOCK_SAML_PORT = 8889;

    private static MockSAMLServer mockSAMLServer;
    private static String keycloakBaseUrl;
    private static GenericContainer<?> keycloak;

    @BeforeAll
    static void setup() throws Exception {
        // Start mock SAML server on the host with base URL that matches what Keycloak will see
        // Keycloak runs in Docker and accesses the host via host.testcontainers.internal
        String baseUrlForKeycloak = "http://host.testcontainers.internal:" + MOCK_SAML_PORT;
        mockSAMLServer = new MockSAMLServer(MOCK_SAML_PORT, baseUrlForKeycloak);
        mockSAMLServer.start();
        System.out.println(
                "Mock SAML server started on port " + MOCK_SAML_PORT + " with base URL " + baseUrlForKeycloak);

        // Expose the host port so Docker containers can access it
        Testcontainers.exposeHostPorts(MOCK_SAML_PORT);

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
        if (mockSAMLServer != null) {
            mockSAMLServer.close();
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
            client.setRedirectUris(java.util.List.of("http://localhost:8080/callback", "*"));
            client.setWebOrigins(java.util.List.of("*"));
            adminClient.realm(REALM_NAME).clients().create(client);
            System.out.println("Created client: " + CLIENT_ID);

            // Create cookieless SAML identity provider
            IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
            idp.setAlias(IDP_ALIAS);
            idp.setProviderId("cookieless-saml"); // Our custom provider ID
            idp.setEnabled(true);
            idp.setTrustEmail(true);
            idp.setFirstBrokerLoginFlowAlias("first broker login");

            // Configure the IDP to point to our mock server
            // Using host.testcontainers.internal for Docker-for-Mac/Windows
            String mockServerHost = "host.testcontainers.internal";
            Map<String, String> config = new HashMap<>();
            config.put("singleSignOnServiceUrl", "http://" + mockServerHost + ":" + MOCK_SAML_PORT + "/sso");
            config.put("nameIDPolicyFormat", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            config.put("principalType", "SUBJECT");
            config.put("postBindingAuthnRequest", "false"); // Use redirect binding
            config.put("postBindingResponse", "true"); // Response comes via POST
            config.put("validateSignature", "false"); // Mock server uses unsigned assertions
            config.put("wantAuthnRequestsSigned", "false");
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
     * Tests the cookieless SAML callback scenario.
     *
     * <p>This simulates a real-world flow where:
     * <ol>
     *   <li>User starts login in their browser (cookies are set)
     *   <li>Keycloak redirects to external SAML IDP
     *   <li>External IDP authenticates user (possibly via native app)
     *   <li>IDP returns SAML Response to a NEW browser instance (no cookies)
     * </ol>
     *
     * <p>The cookieless extension embeds the session ID in the RelayState parameter, allowing
     * Keycloak to recover the session without relying on cookies.
     *
     * <p>Note: The initial steps still use cookies to establish the session and navigate through
     * Keycloak's internal redirects - this is the original browser. The key test is that the
     * CALLBACK works without cookies.
     */
    @Test
    void testCookielessSAMLFlow() {
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

        // This should redirect to the external SAML IDP's SSO endpoint
        assertThat(brokerLoginResponse.statusCode())
                .as("Should redirect to external IDP")
                .isIn(302, 303);

        String idpRedirectUrl = brokerLoginResponse.header("Location");
        System.out.println("IDP redirect URL: " + idpRedirectUrl);

        // Verify this goes to the mock SAML server's SSO endpoint
        assertThat(idpRedirectUrl)
                .as("Should redirect to mock SAML SSO endpoint")
                .contains("/sso");
        assertThat(idpRedirectUrl).contains("SAMLRequest=");
        assertThat(idpRedirectUrl).contains("RelayState=");

        // Extract RelayState from redirect URL - this contains the embedded session ID
        String relayState = extractQueryParam(idpRedirectUrl, "RelayState");
        System.out.println("RelayState parameter (contains embedded session ID): " + relayState);
        assertThat(relayState).isNotNull();

        // Extract SAMLRequest and get the AuthnRequest ID for InResponseTo
        String samlRequest = extractQueryParam(idpRedirectUrl, "SAMLRequest");
        String authnRequestId = extractAuthnRequestId(samlRequest);
        System.out.println("AuthnRequest ID: " + authnRequestId);
        assertThat(authnRequestId).isNotNull();

        // Step 3: Simulate the external SAML IDP authentication
        // In a real scenario, the external IDP would authenticate the user,
        // possibly opening a native app, then POST a SAML Response back to Keycloak
        String callbackUrl = "/realms/" + REALM_NAME + "/broker/" + IDP_ALIAS + "/endpoint";

        // Create a mock SAML Response (Base64 encoded) with correct InResponseTo
        String samlResponse = createMockSAMLResponse(authnRequestId);
        String encodedSamlResponse = Base64.getEncoder().encodeToString(samlResponse.getBytes(StandardCharsets.UTF_8));

        // ============================================================
        // CRITICAL: This is the cookieless callback test
        // ============================================================
        // Step 4: POST SAML Response to Keycloak's broker callback endpoint WITHOUT cookies
        // This simulates a NEW browser instance (e.g., opened by native app)
        // that has no access to the original session cookies.
        //
        // Without the cookieless extension, this would fail with an error
        // because Keycloak couldn't find the auth session without cookies.
        //
        // With the extension, the session ID is extracted from the RelayState
        // parameter and the session is recovered directly.
        Response callbackResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                // NO COOKIES - simulating new browser instance
                .contentType("application/x-www-form-urlencoded")
                .formParam("SAMLResponse", encodedSamlResponse)
                .formParam("RelayState", relayState)
                .when()
                .post(callbackUrl);

        System.out.println("Callback response status: " + callbackResponse.statusCode());
        System.out.println("Callback response headers: " + callbackResponse.headers());
        String callbackBody = callbackResponse.body().asString();
        if (callbackResponse.statusCode() != 302 && callbackResponse.statusCode() != 303) {
            System.out.println("Callback response body: " + callbackBody);
            // Print Keycloak container logs to diagnose the error
            System.out.println("=== Keycloak Container Logs ===");
            System.out.println(keycloak.getLogs());
            System.out.println("=== End Keycloak Logs ===");
        }

        // With cookieless SAML IDP, this MUST redirect (302/303) to continue the auth flow
        // After successful SAML assertion processing, Keycloak redirects to:
        // - First broker login page (new user needs to review/link account), or
        // - Directly to the client redirect_uri (if auto-linking is configured)
        //
        // Without our extension, this would fail with "identity_provider_missing_state" error
        assertThat(callbackResponse.statusCode())
                .as(
                        "Cookieless SAML callback must redirect to continue auth flow (got %d)",
                        callbackResponse.statusCode())
                .isIn(302, 303);

        String nextLocation = callbackResponse.header("Location");
        System.out.println("Next location: " + nextLocation);

        // Verify it's not an error redirect
        assertThat(nextLocation)
                .as("Should not redirect to error page")
                .doesNotContain("identity_provider_missing_state")
                .doesNotContain("identity_provider_error");

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
                        .formParam("username", "mock-saml-user")
                        .formParam("email", "mockuser@example.com")
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

        System.out.println("SUCCESS: User logged in via cookieless SAML IDP, received auth code: "
                + authCode.substring(0, Math.min(20, authCode.length())) + "...");
    }

    /**
     * Tests that the standard cookie-based SAML flow still works with the extension.
     *
     * <p>This is a regression test to ensure the cookieless extension doesn't break the normal flow
     * where cookies ARE available (e.g., same browser instance throughout the entire flow).
     */
    @Test
    void testStandardSAMLFlowWithCookiesStillWorks() {
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
        String relayState = extractQueryParam(idpRedirectUrl, "RelayState");

        // Extract SAMLRequest and get the AuthnRequest ID for InResponseTo
        String samlRequest = extractQueryParam(idpRedirectUrl, "SAMLRequest");
        String authnRequestId = extractAuthnRequestId(samlRequest);

        // Create a mock SAML Response with correct InResponseTo
        String samlResponse = createMockSAMLResponse(authnRequestId);
        String encodedSamlResponse = Base64.getEncoder().encodeToString(samlResponse.getBytes(StandardCharsets.UTF_8));

        // Callback WITH cookies - standard flow where browser keeps same session
        String callbackUrl = "/realms/" + REALM_NAME + "/broker/" + IDP_ALIAS + "/endpoint";

        Response callbackResponse = given().config(RestAssured.config()
                        .redirect(RedirectConfig.redirectConfig().followRedirects(false)))
                .cookies(allCookies) // Cookies included - same browser instance
                .contentType("application/x-www-form-urlencoded")
                .formParam("SAMLResponse", encodedSamlResponse)
                .formParam("RelayState", relayState)
                .when()
                .post(callbackUrl);

        System.out.println("Standard SAML flow callback status: " + callbackResponse.statusCode());

        // Must redirect to continue the auth flow
        assertThat(callbackResponse.statusCode())
                .as("Standard SAML flow callback must redirect")
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
                        .formParam("username", "mock-saml-user-standard")
                        .formParam("email", "mockuser-standard@example.com")
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

        System.out.println("Standard SAML flow final URL: " + currentUrl);

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

        System.out.println("SUCCESS: Standard SAML flow completed, received auth code: "
                + authCode.substring(0, Math.min(20, authCode.length())) + "...");
    }

    private String createMockSAMLResponse(String inResponseTo) {
        String responseId = "_" + java.util.UUID.randomUUID().toString();
        String assertionId = "_" + java.util.UUID.randomUUID().toString();
        java.time.Instant now = java.time.Instant.now();
        String issueInstant = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .withZone(java.time.ZoneOffset.UTC)
                .format(now);
        String notOnOrAfter = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .withZone(java.time.ZoneOffset.UTC)
                .format(now.plusSeconds(300));
        String notBefore = java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .withZone(java.time.ZoneOffset.UTC)
                .format(now.minusSeconds(60));

        String destination = keycloakBaseUrl + "/realms/" + REALM_NAME + "/broker/" + IDP_ALIAS + "/endpoint";
        String audience = keycloakBaseUrl + "/realms/" + REALM_NAME;
        String issuer = mockSAMLServer.getEntityId();

        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                ID="%s"
                                Version="2.0"
                                IssueInstant="%s"
                                Destination="%s"
                                InResponseTo="%s">
                    <saml:Issuer>%s</saml:Issuer>
                    <samlp:Status>
                        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
                    </samlp:Status>
                    <saml:Assertion ID="%s"
                                    Version="2.0"
                                    IssueInstant="%s">
                        <saml:Issuer>%s</saml:Issuer>
                        <saml:Subject>
                            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">mock-saml-user</saml:NameID>
                            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                                <saml:SubjectConfirmationData NotOnOrAfter="%s"
                                                              Recipient="%s"
                                                              InResponseTo="%s"/>
                            </saml:SubjectConfirmation>
                        </saml:Subject>
                        <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
                            <saml:AudienceRestriction>
                                <saml:Audience>%s</saml:Audience>
                            </saml:AudienceRestriction>
                        </saml:Conditions>
                        <saml:AuthnStatement AuthnInstant="%s" SessionIndex="%s">
                            <saml:AuthnContext>
                                <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                            </saml:AuthnContext>
                        </saml:AuthnStatement>
                        <saml:AttributeStatement>
                            <saml:Attribute Name="email">
                                <saml:AttributeValue>mockuser@example.com</saml:AttributeValue>
                            </saml:Attribute>
                        </saml:AttributeStatement>
                    </saml:Assertion>
                </samlp:Response>
                """
                .formatted(
                        responseId,
                        issueInstant,
                        destination,
                        inResponseTo,
                        issuer,
                        assertionId,
                        issueInstant,
                        issuer,
                        notOnOrAfter,
                        destination,
                        inResponseTo,
                        notBefore,
                        notOnOrAfter,
                        audience,
                        issueInstant,
                        assertionId);
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

    private String extractFormAction(String html) {
        // Simple regex to extract form action
        Pattern pattern = Pattern.compile("action=\"([^\"]+)\"");
        Matcher matcher = pattern.matcher(html);
        if (matcher.find()) {
            String action = matcher.group(1);
            // Decode HTML entities
            return action.replace("&amp;", "&");
        }
        return null;
    }

    /**
     * Extracts the AuthnRequest ID from a SAML redirect-binding SAMLRequest parameter.
     * The SAMLRequest is DEFLATE compressed then Base64 encoded.
     */
    private String extractAuthnRequestId(String samlRequest) {
        try {
            System.out.println(
                    "SAMLRequest (first 100 chars): " + samlRequest.substring(0, Math.min(100, samlRequest.length())));
            // The SAMLRequest is Base64 encoded (standard, not URL-safe)
            // Replace any URL-encoded + that became spaces
            String cleanedSamlRequest = samlRequest.replace(" ", "+");
            byte[] decoded = Base64.getDecoder().decode(cleanedSamlRequest);

            // Inflate (decompress DEFLATE)
            Inflater inflater = new Inflater(true); // nowrap=true for raw DEFLATE
            ByteArrayInputStream bais = new ByteArrayInputStream(decoded);
            InflaterInputStream iis = new InflaterInputStream(bais, inflater);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int len;
            while ((len = iis.read(buffer)) > 0) {
                baos.write(buffer, 0, len);
            }
            String authnRequest = baos.toString(StandardCharsets.UTF_8);
            System.out.println(
                    "Decoded AuthnRequest: " + authnRequest.substring(0, Math.min(500, authnRequest.length())));

            // Extract the ID attribute using regex
            Pattern pattern = Pattern.compile("ID=\"([^\"]+)\"");
            Matcher matcher = pattern.matcher(authnRequest);
            if (matcher.find()) {
                return matcher.group(1);
            }
        } catch (Exception e) {
            System.out.println("Failed to extract AuthnRequest ID: " + e.getMessage());
        }
        return null;
    }
}
