package com.github.dominikschlosser.keycloak.broker.saml;

import com.github.dominikschlosser.keycloak.broker.CookielessIdentityBrokerState;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Cookieless SAML Identity Provider.
 *
 * <p>This provider extends the standard SAML Identity Provider to support scenarios where the
 * callback from the external IDP arrives without browser cookies.
 *
 * <p>The session ID is embedded in the RelayState parameter using a compact binary encoding to fit
 * within the SAML 80-byte limit. The data is signed using HMAC to prevent tampering.
 *
 * <p><b>IMPORTANT:</b> The RelayState is fully consumed by this extension and cannot be used for
 * other purposes when using the cookieless SAML IDP.
 *
 * <p>Compact binary format (52 bytes → 70 chars Base64):
 *
 * <pre>
 * [sessionId:16][hmac:8][clientId:16][tabId:4][code:8]
 * </pre>
 */
public class CookielessSAMLIdentityProvider extends SAMLIdentityProvider {

    private static final Logger logger = Logger.getLogger(CookielessSAMLIdentityProvider.class);

    private final DestinationValidator destinationValidator;

    public CookielessSAMLIdentityProvider(
            KeycloakSession session, SAMLIdentityProviderConfig config, DestinationValidator destinationValidator) {
        super(session, config, destinationValidator);
        this.destinationValidator = destinationValidator;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new CookielessSAMLEndpoint(session, this, getConfig(), callback, destinationValidator);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            RealmModel realm = request.getRealm();
            AuthenticationSessionModel authSession = request.getAuthenticationSession();
            RootAuthenticationSessionModel rootSession = authSession.getParentSession();

            // Create cookieless RelayState with session ID
            // We need to store the session info before the parent builds the SAML request
            byte[] hmacKey = CookielessIdentityBrokerState.getHmacKey(session, realm);

            // Get the code from the state - the parent's state contains the verification code
            String code = request.getState().getDecodedState();
            if (code == null || code.isEmpty()) {
                code = "default"; // Fallback code
            }

            CookielessIdentityBrokerState cookielessState = CookielessIdentityBrokerState.encodeSAML(
                    rootSession.getId(),
                    code,
                    authSession.getTabId(),
                    authSession.getClient().getId(),
                    hmacKey);

            // Store the cookieless state in auth session so we can retrieve it in callback
            authSession.setAuthNote("cookieless_relay_state", cookielessState.getEncoded());

            // Call parent's performLogin which will build and send the SAML AuthnRequest
            // The parent will use its own RelayState, but we'll extract it from the redirect
            Response parentResponse = super.performLogin(request);

            // If the response is a redirect, we need to replace the RelayState
            if (parentResponse.getStatus() == 302 || parentResponse.getStatus() == 303) {
                Object locationObj = parentResponse.getMetadata().getFirst("Location");
                String location = locationObj != null ? locationObj.toString() : null;
                if (location != null && location.contains("RelayState=")) {
                    // Replace the RelayState parameter with our cookieless state
                    location = replaceRelayState(location, cookielessState.getEncoded());
                    return Response.status(parentResponse.getStatus())
                            .header("Location", location)
                            .build();
                }
            }

            return parentResponse;
        } catch (Exception e) {
            logger.error("Failed to perform SAML login", e);
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    private String replaceRelayState(String url, String newRelayState) {
        // URL-encode the new relay state
        String encodedRelayState;
        try {
            encodedRelayState = java.net.URLEncoder.encode(newRelayState, StandardCharsets.UTF_8);
        } catch (Exception e) {
            encodedRelayState = newRelayState;
        }

        // Replace existing RelayState parameter
        return url.replaceFirst("RelayState=[^&]*", "RelayState=" + encodedRelayState);
    }
}
