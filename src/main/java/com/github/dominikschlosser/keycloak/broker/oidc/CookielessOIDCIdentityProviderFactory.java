package com.github.dominikschlosser.keycloak.broker.oidc;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * Factory for creating Cookieless OIDC Identity Provider instances.
 *
 * <p>The provider ID is "cookieless-oidc" which distinguishes it from the standard "oidc" provider.
 */
public class CookielessOIDCIdentityProviderFactory extends OIDCIdentityProviderFactory {

    public static final String PROVIDER_ID = "cookieless-oidc";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "Cookieless OpenID Connect v1.0";
    }

    @Override
    public CookielessOIDCIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new CookielessOIDCIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }
}
