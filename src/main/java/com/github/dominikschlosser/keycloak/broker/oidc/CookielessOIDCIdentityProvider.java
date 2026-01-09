package com.github.dominikschlosser.keycloak.broker.oidc;

import com.github.dominikschlosser.keycloak.broker.CookielessIdentityBrokerState;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;
import org.jboss.logging.Logger;
import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.Constants;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;

/**
 * Cookieless OIDC Identity Provider.
 *
 * <p>This provider extends the standard OIDC Identity Provider to support scenarios where the
 * callback from the external IDP arrives without browser cookies (e.g., when the external IDP opens
 * a native app that returns in a new browser instance).
 *
 * <p>The session ID is embedded in the state parameter and signed using HMAC to prevent tampering.
 * On callback, the session is recovered directly from the state parameter without relying on
 * cookies.
 */
public class CookielessOIDCIdentityProvider extends OIDCIdentityProvider {

    private static final Logger logger = Logger.getLogger(CookielessOIDCIdentityProvider.class);

    public CookielessOIDCIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new CookielessEndpoint(callback, realm, event, this);
    }

    @Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        UriBuilder builder = super.createAuthorizationUrl(request);

        // Replace the standard state with our cookieless state that includes the session ID
        AuthenticationSessionModel authSession = request.getAuthenticationSession();
        RootAuthenticationSessionModel rootSession = authSession.getParentSession();

        byte[] hmacKey = CookielessIdentityBrokerState.getHmacKey(
                session, session.getContext().getRealm());

        CookielessIdentityBrokerState cookielessState = CookielessIdentityBrokerState.encodeOIDC(
                rootSession.getId(),
                request.getState().getDecodedState(),
                authSession.getTabId(),
                authSession.getClient().getId(),
                authSession.getClient().getClientId(),
                null, // clientData not used for OIDC (no size limit)
                hmacKey);

        // Replace the state parameter
        builder.replaceQueryParam(OAUTH2_PARAMETER_STATE, cookielessState.getEncoded());

        return builder;
    }

    /**
     * Custom endpoint that can recover the authentication session from the state parameter without
     * relying on cookies.
     */
    protected class CookielessEndpoint extends Endpoint {

        private final CookielessOIDCIdentityProvider provider;

        public CookielessEndpoint(
                AuthenticationCallback callback,
                RealmModel realm,
                EventBuilder event,
                CookielessOIDCIdentityProvider provider) {
            super(callback, realm, event, provider);
            this.provider = provider;
        }

        @Override
        @GET
        public Response authResponse(
                @QueryParam(OAUTH2_PARAMETER_STATE) String state,
                @QueryParam(OAUTH2_PARAMETER_CODE) String authorizationCode,
                @QueryParam(OAuth2Constants.ERROR) String error,
                @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) String errorDescription) {

            OIDCIdentityProviderConfig providerConfig = provider.getConfig();

            if (state == null) {
                logger.error("Cookieless OIDC callback: state parameter is missing");
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_STATE_ERROR);
            }

            try {
                // Decode the cookieless state and recover the session
                byte[] hmacKey = CookielessIdentityBrokerState.getHmacKey(session, realm);
                CookielessIdentityBrokerState cookielessState =
                        CookielessIdentityBrokerState.decodeOIDC(state, realm, hmacKey);

                // Look up the authentication session directly by ID
                AuthenticationSessionModel authSession = lookupAuthenticationSession(
                        realm,
                        cookielessState.getSessionId(),
                        cookielessState.getClientId(),
                        cookielessState.getTabId());

                if (authSession == null) {
                    logger.errorf(
                            "Cookieless OIDC callback: could not find authentication session. "
                                    + "sessionId=%s, clientId=%s, tabId=%s",
                            cookielessState.getSessionId(), cookielessState.getClientId(), cookielessState.getTabId());
                    return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }

                session.getContext().setAuthenticationSession(authSession);

                // Handle errors from the IDP
                if (error != null) {
                    logger.warnf("Cookieless OIDC callback received error: %s - %s", error, errorDescription);
                    if (error.equals(ACCESS_DENIED)) {
                        return callback.cancelled(providerConfig);
                    } else if (error.equals(OAuthErrorException.LOGIN_REQUIRED)
                            || error.equals(OAuthErrorException.INTERACTION_REQUIRED)) {
                        return callback.error(providerConfig, error);
                    } else if (error.equals(OAuthErrorException.TEMPORARILY_UNAVAILABLE)
                            && Constants.AUTHENTICATION_EXPIRED_MESSAGE.equals(errorDescription)) {
                        return callback.retryLogin(provider, authSession);
                    } else {
                        return callback.error(providerConfig, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                }

                if (authorizationCode == null) {
                    logger.error("Cookieless OIDC callback: authorization code is missing");
                    return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_MISSING_CODE_OR_ERROR_ERROR);
                }

                // Use parent's token request generation and exchange
                var tokenRequest = generateTokenRequest(authorizationCode);
                String response;
                try {
                    var tokenResponse = tokenRequest.asResponse();
                    int status = tokenResponse.getStatus();
                    boolean success = status >= 200 && status < 400;
                    response = tokenResponse.asString();

                    if (!success) {
                        logger.errorf(
                                "Unexpected response from token endpoint. status=%s, response=%s", status, response);
                        return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                    }
                } catch (Exception e) {
                    logger.error("Failed to exchange authorization code for tokens", e);
                    return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
                }

                // Extract federated identity from token response
                BrokeredIdentityContext federatedIdentity = provider.getFederatedIdentity(response);

                if (Boolean.TRUE.equals(providerConfig.isStoreToken())) {
                    if (federatedIdentity.getToken() == null) {
                        federatedIdentity.setToken(response);
                    }
                }

                federatedIdentity.setIdp(provider);
                federatedIdentity.setAuthenticationSession(authSession);

                return callback.authenticated(federatedIdentity);

            } catch (SecurityException e) {
                logger.errorf(e, "Security error during cookieless OIDC callback: %s", e.getMessage());
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            } catch (WebApplicationException e) {
                return e.getResponse();
            } catch (IdentityBrokerException e) {
                if (e.getMessageCode() != null) {
                    return errorIdentityProviderLogin(e.getMessageCode());
                }
                logger.error("Failed to process cookieless OIDC callback", e);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            } catch (Exception e) {
                logger.error("Failed to process cookieless OIDC callback", e);
                return errorIdentityProviderLogin(Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
            }
        }

        /** Look up the authentication session directly by ID, without relying on cookies. */
        private AuthenticationSessionModel lookupAuthenticationSession(
                RealmModel realm, String sessionId, String clientId, String tabId) {

            // Get the root authentication session by ID
            RootAuthenticationSessionModel rootSession =
                    session.authenticationSessions().getRootAuthenticationSession(realm, sessionId);

            if (rootSession == null) {
                logger.debugf("Root authentication session not found: %s", sessionId);
                return null;
            }

            // Find the client
            ClientModel client = realm.getClientByClientId(clientId);
            if (client == null) {
                logger.debugf("Client not found: %s", clientId);
                return null;
            }

            // Get the specific authentication session for this client and tab
            AuthenticationSessionModel authSession = rootSession.getAuthenticationSession(client, tabId);
            if (authSession == null) {
                logger.debugf("Authentication session not found for client=%s, tabId=%s", clientId, tabId);
                return null;
            }

            return authSession;
        }

        private Response errorIdentityProviderLogin(String message) {
            event.event(EventType.IDENTITY_PROVIDER_LOGIN);
            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, message);
        }
    }
}
