package com.github.dominikschlosser.keycloak.broker.saml;

import com.github.dominikschlosser.keycloak.broker.CookielessIdentityBrokerState;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.models.ClientModel;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Custom SAML Endpoint that can recover the authentication session from the RelayState without
 * relying on cookies.
 *
 * <p>This endpoint wraps the callback to provide a custom authentication session lookup that uses
 * the session ID embedded in the RelayState parameter.
 */
public class CookielessSAMLEndpoint extends SAMLEndpoint {

    private static final Logger logger = Logger.getLogger(CookielessSAMLEndpoint.class);

    private final KeycloakSession session;
    private final RealmModel realm;

    public CookielessSAMLEndpoint(
            KeycloakSession session,
            SAMLIdentityProvider provider,
            SAMLIdentityProviderConfig config,
            UserAuthenticationIdentityProvider.AuthenticationCallback callback,
            DestinationValidator destinationValidator) {
        super(session, provider, config, new CookielessAuthenticationCallback(session, callback), destinationValidator);
        this.session = session;
        this.realm = session.getContext().getRealm();
    }

    /**
     * Wrapper callback that intercepts getAndVerifyAuthenticationSession calls and uses our
     * cookieless session lookup.
     */
    private static class CookielessAuthenticationCallback
            implements UserAuthenticationIdentityProvider.AuthenticationCallback {

        private final KeycloakSession session;
        private final UserAuthenticationIdentityProvider.AuthenticationCallback delegate;

        public CookielessAuthenticationCallback(
                KeycloakSession session, UserAuthenticationIdentityProvider.AuthenticationCallback delegate) {
            this.session = session;
            this.delegate = delegate;
        }

        @Override
        public AuthenticationSessionModel getAndVerifyAuthenticationSession(String encodedCode) {
            // Try our cookieless decoding first
            try {
                RealmModel realm = session.getContext().getRealm();
                byte[] hmacKey = CookielessIdentityBrokerState.getHmacKey(session, realm);

                CookielessIdentityBrokerState cookielessState =
                        CookielessIdentityBrokerState.decodeSAML(encodedCode, hmacKey);

                // Look up the session directly by ID
                RootAuthenticationSessionModel rootSession = session.authenticationSessions()
                        .getRootAuthenticationSession(realm, cookielessState.getSessionId());

                if (rootSession != null) {
                    // For SAML compact encoding, clientId is the DB ID (UUID), not the clientId
                    // string
                    ClientModel client = realm.getClientById(cookielessState.getClientId());
                    if (client == null) {
                        logger.debugf("Client not found by ID: %s", cookielessState.getClientId());
                        // Fall back to delegate
                        return delegate.getAndVerifyAuthenticationSession(encodedCode);
                    }

                    // TabId is hashed in SAML compact encoding, so we need to find the right tab
                    // For now, try to get any authentication session for this client
                    // In production, you might want to iterate through tabs to find the right one
                    AuthenticationSessionModel authSession = null;
                    for (var tab : rootSession.getAuthenticationSessions().values()) {
                        if (tab.getClient().getId().equals(client.getId())) {
                            authSession = tab;
                            break;
                        }
                    }

                    if (authSession != null) {
                        logger.debugf(
                                "Cookieless SAML: Found authentication session via state parameter. "
                                        + "sessionId=%s, clientId=%s",
                                cookielessState.getSessionId(), client.getClientId());
                        return authSession;
                    }
                }
            } catch (Exception e) {
                logger.debugf(
                        e, "Failed to decode cookieless SAML state, falling back to delegate: %s", e.getMessage());
            }

            // Fall back to standard callback (which may use cookies)
            return delegate.getAndVerifyAuthenticationSession(encodedCode);
        }

        @Override
        public Response authenticated(BrokeredIdentityContext context) {
            return delegate.authenticated(context);
        }

        @Override
        public Response cancelled(IdentityProviderModel idpConfig) {
            return delegate.cancelled(idpConfig);
        }

        @Override
        public Response retryLogin(
                UserAuthenticationIdentityProvider<?> identityProvider, AuthenticationSessionModel authSession) {
            return delegate.retryLogin(identityProvider, authSession);
        }

        @Override
        public Response error(IdentityProviderModel idpConfig, String message) {
            return delegate.error(idpConfig, message);
        }
    }
}
