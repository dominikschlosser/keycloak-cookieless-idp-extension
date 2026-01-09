package com.github.dominikschlosser.keycloak.broker.saml;

import org.keycloak.Config.Scope;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * Factory for creating Cookieless SAML Identity Provider instances.
 *
 * <p>The provider ID is "cookieless-saml" which distinguishes it from the standard "saml" provider.
 *
 * <p><b>IMPORTANT:</b> This provider fully consumes the SAML RelayState parameter to transport
 * session information. The RelayState cannot be used for other purposes when using this provider.
 */
public class CookielessSAMLIdentityProviderFactory extends SAMLIdentityProviderFactory {

    public static final String PROVIDER_ID = "cookieless-saml";

    private DestinationValidator destinationValidator;

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getName() {
        return "Cookieless SAML v2.0";
    }

    @Override
    public CookielessSAMLIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new CookielessSAMLIdentityProvider(session, new SAMLIdentityProviderConfig(model), destinationValidator);
    }

    @Override
    public void init(Scope config) {
        super.init(config);
        this.destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
    }
}
