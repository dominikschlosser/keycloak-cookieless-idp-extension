package com.github.dominikschlosser.keycloak.mock;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A minimal mock SAML Identity Provider for testing purposes. Implements just enough of the SAML
 * protocol to test Keycloak's IDP broker flow.
 */
public class MockSAMLServer implements AutoCloseable {

    private static final DateTimeFormatter SAML_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    private final HttpServer server;
    private final int port;
    private final String entityId;
    private final String baseUrl;

    private String lastReceivedRelayState;
    private String lastReceivedAuthnRequestId;
    private String lastReceivedAcsUrl;

    public MockSAMLServer(int port) throws IOException {
        this(port, "http://localhost:" + port);
    }

    public MockSAMLServer(int port, String baseUrl) throws IOException {
        this.port = port;
        this.baseUrl = baseUrl;
        this.entityId = baseUrl + "/saml";
        this.server = HttpServer.create(new InetSocketAddress(port), 0);
        this.server.setExecutor(Executors.newFixedThreadPool(2));

        setupEndpoints();
    }

    private void setupEndpoints() {
        // SSO endpoint (handles AuthnRequest via redirect binding)
        server.createContext("/sso", this::handleSSORedirect);

        // SSO POST endpoint
        server.createContext("/sso/post", this::handleSSOPost);

        // Metadata endpoint
        server.createContext("/metadata", this::handleMetadata);
    }

    private void handleSSORedirect(HttpExchange exchange) throws IOException {
        Map<String, String> params = parseQueryParams(exchange.getRequestURI().getQuery());

        lastReceivedRelayState = params.get("RelayState");
        String samlRequest = params.get("SAMLRequest");

        if (samlRequest != null) {
            parseAuthnRequest(samlRequest, true);
        }

        // Return an HTML page with auto-submit form containing SAML Response
        String samlResponse = createSAMLResponse();
        String encodedResponse = Base64.getEncoder().encodeToString(samlResponse.getBytes(StandardCharsets.UTF_8));

        String html = createAutoSubmitForm(encodedResponse, lastReceivedRelayState);

        byte[] response = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html");
        exchange.sendResponseHeaders(200, response.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    private void handleSSOPost(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String, String> params = parseFormParams(body);

        lastReceivedRelayState = params.get("RelayState");
        String samlRequest = params.get("SAMLRequest");

        if (samlRequest != null) {
            parseAuthnRequest(samlRequest, false);
        }

        // Return an HTML page with auto-submit form containing SAML Response
        String samlResponse = createSAMLResponse();
        String encodedResponse = Base64.getEncoder().encodeToString(samlResponse.getBytes(StandardCharsets.UTF_8));

        String html = createAutoSubmitForm(encodedResponse, lastReceivedRelayState);

        byte[] response = html.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html");
        exchange.sendResponseHeaders(200, response.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    private void handleMetadata(HttpExchange exchange) throws IOException {
        String metadata =
                """
                <?xml version="1.0" encoding="UTF-8"?>
                <EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
                                  entityID="%s">
                    <IDPSSODescriptor WantAuthnRequestsSigned="false"
                                      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                        <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</NameIDFormat>
                        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                                             Location="%s/sso"/>
                        <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                                             Location="%s/sso/post"/>
                    </IDPSSODescriptor>
                </EntityDescriptor>
                """
                        .formatted(entityId, getBaseUrl(), getBaseUrl());

        byte[] response = metadata.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/xml");
        exchange.sendResponseHeaders(200, response.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response);
        }
    }

    private void parseAuthnRequest(String encodedRequest, boolean deflated) {
        try {
            byte[] decoded = Base64.getDecoder().decode(encodedRequest);
            byte[] xml;

            if (deflated) {
                // HTTP-Redirect binding uses DEFLATE compression
                Inflater inflater = new Inflater(true);
                try (InflaterInputStream iis = new InflaterInputStream(new ByteArrayInputStream(decoded), inflater)) {
                    xml = iis.readAllBytes();
                }
            } else {
                xml = decoded;
            }

            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(xml));

            Element authnRequest = doc.getDocumentElement();
            lastReceivedAuthnRequestId = authnRequest.getAttribute("ID");
            lastReceivedAcsUrl = authnRequest.getAttribute("AssertionConsumerServiceURL");

            System.out.println("Received AuthnRequest ID: " + lastReceivedAuthnRequestId);
            System.out.println("ACS URL: " + lastReceivedAcsUrl);

        } catch (Exception e) {
            System.err.println("Failed to parse AuthnRequest: " + e.getMessage());
            // Use defaults for testing
            lastReceivedAuthnRequestId = "_" + UUID.randomUUID().toString();
            lastReceivedAcsUrl = "http://localhost:8080/realms/test-realm/broker/cookieless-saml-idp/endpoint";
        }
    }

    private String createSAMLResponse() {
        String responseId = "_" + UUID.randomUUID().toString();
        String assertionId = "_" + UUID.randomUUID().toString();
        Instant now = Instant.now();
        String issueInstant = SAML_DATE_FORMAT.format(now);
        String notOnOrAfter = SAML_DATE_FORMAT.format(now.plusSeconds(300));
        String notBefore = SAML_DATE_FORMAT.format(now.minusSeconds(60));

        String inResponseTo = lastReceivedAuthnRequestId != null ? lastReceivedAuthnRequestId : "";
        String destination = lastReceivedAcsUrl != null
                ? lastReceivedAcsUrl
                : "http://localhost:8080/realms/test-realm/broker/cookieless-saml-idp/endpoint";

        // Create unsigned SAML Response for testing
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
                    <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                    ID="%s"
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
                            <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                                <saml:AttributeValue>mockuser@example.com</saml:AttributeValue>
                            </saml:Attribute>
                            <saml:Attribute Name="firstName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                                <saml:AttributeValue>Mock</saml:AttributeValue>
                            </saml:Attribute>
                            <saml:Attribute Name="lastName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                                <saml:AttributeValue>User</saml:AttributeValue>
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
                        entityId,
                        assertionId,
                        issueInstant,
                        entityId,
                        notOnOrAfter,
                        destination,
                        inResponseTo,
                        notBefore,
                        notOnOrAfter,
                        destination, // Audience = SP entity ID (ACS URL base)
                        issueInstant,
                        assertionId);
    }

    private String createAutoSubmitForm(String samlResponse, String relayState) {
        String relayStateField = relayState != null
                ? "<input type=\"hidden\" name=\"RelayState\" value=\"" + escapeHtml(relayState) + "\"/>"
                : "";

        String acsUrl = lastReceivedAcsUrl != null
                ? lastReceivedAcsUrl
                : "http://localhost:8080/realms/test-realm/broker/cookieless-saml-idp/endpoint";

        return """
                <!DOCTYPE html>
                <html>
                <head><title>SAML Response</title></head>
                <body onload="document.forms[0].submit()">
                    <form method="POST" action="%s">
                        <input type="hidden" name="SAMLResponse" value="%s"/>
                        %s
                        <noscript>
                            <input type="submit" value="Continue"/>
                        </noscript>
                    </form>
                </body>
                </html>
                """
                .formatted(acsUrl, samlResponse, relayStateField);
    }

    private String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
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
        System.out.println("Mock SAML server started on port " + port);
    }

    @Override
    public void close() {
        server.stop(0);
    }

    public int getPort() {
        return port;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getEntityId() {
        return entityId;
    }

    public String getSSOUrl() {
        return getBaseUrl() + "/sso";
    }

    public String getMetadataUrl() {
        return getBaseUrl() + "/metadata";
    }

    public String getLastReceivedRelayState() {
        return lastReceivedRelayState;
    }
}
