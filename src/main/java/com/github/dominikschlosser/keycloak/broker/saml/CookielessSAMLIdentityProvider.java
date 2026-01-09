package com.github.dominikschlosser.keycloak.broker.saml;

import com.github.dominikschlosser.keycloak.broker.CookielessIdentityBrokerState;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.dom.saml.v2.protocol.AuthnRequestType;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.SAML2AuthnRequestBuilder;
import org.keycloak.saml.SAML2NameIDPolicyBuilder;
import org.keycloak.saml.SAML2RequestedAuthnContextBuilder;
import org.keycloak.saml.SignatureAlgorithm;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import org.keycloak.saml.processing.core.util.KeycloakKeySamlExtensionGenerator;
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
            UriInfo uriInfo = request.getUriInfo();
            RealmModel realm = request.getRealm();
            AuthenticationSessionModel authSession = request.getAuthenticationSession();
            RootAuthenticationSessionModel rootSession = authSession.getParentSession();

            // Create cookieless RelayState with session ID
            byte[] hmacKey = CookielessIdentityBrokerState.getHmacKey(session, realm);
            CookielessIdentityBrokerState cookielessState = CookielessIdentityBrokerState.encodeSAML(
                    rootSession.getId(),
                    request.getState().getDecodedState(),
                    authSession.getTabId(),
                    authSession.getClient().getId(),
                    hmacKey);

            String issuerURL = getEntityId(uriInfo, realm);
            String destinationUrl = getConfig().getSingleSignOnServiceUrl();
            String nameIDPolicyFormat = getConfig().getNameIDPolicyFormat();

            if (nameIDPolicyFormat == null) {
                nameIDPolicyFormat = JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
            }

            String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();
            String assertionConsumerServiceUrl = request.getRedirectUri();

            if (getConfig().isArtifactBindingResponse()) {
                protocolBinding = JBossSAMLURIConstants.SAML_HTTP_ARTIFACT_BINDING.get();
            } else if (getConfig().isPostBindingResponse()) {
                protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
            }

            SAML2RequestedAuthnContextBuilder requestedAuthnContext = new SAML2RequestedAuthnContextBuilder()
                    .setComparison(getConfig().getAuthnContextComparisonType());

            for (String authnContextClassRef : getAuthnContextClassRefUris()) {
                requestedAuthnContext.addAuthnContextClassRef(authnContextClassRef);
            }

            for (String authnContextDeclRef : getAuthnContextDeclRefUris()) {
                requestedAuthnContext.addAuthnContextDeclRef(authnContextDeclRef);
            }

            Integer attributeConsumingServiceIndex = getConfig().getAttributeConsumingServiceIndex();
            String loginHint = getConfig().isLoginHint()
                    ? authSession.getClientNote(org.keycloak.protocol.oidc.OIDCLoginProtocol.LOGIN_HINT_PARAM)
                    : null;

            Boolean allowCreate = null;
            if (getConfig().getConfig().get(SAMLIdentityProviderConfig.ALLOW_CREATE) != null) {
                allowCreate = Boolean.valueOf(getConfig().getConfig().get(SAMLIdentityProviderConfig.ALLOW_CREATE));
            }

            SAML2AuthnRequestBuilder authnRequestBuilder = new SAML2AuthnRequestBuilder()
                    .assertionConsumerUrl(assertionConsumerServiceUrl)
                    .destination(destinationUrl)
                    .issuer(issuerURL)
                    .forceAuthn(getConfig().isForceAuthn())
                    .protocolBinding(protocolBinding)
                    .nameIdPolicy(
                            SAML2NameIDPolicyBuilder.format(nameIDPolicyFormat).setAllowCreate(allowCreate))
                    .attributeConsumingServiceIndex(attributeConsumingServiceIndex)
                    .requestedAuthnContext(requestedAuthnContext)
                    .subject(loginHint);

            JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session)
                    .relayState(cookielessState.getEncoded()); // Use our cookieless state as
            // RelayState

            boolean postBinding = getConfig().isPostBindingAuthnRequest();

            if (getConfig().isWantAuthnRequestsSigned()) {
                KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

                String keyName = getConfig()
                        .getXmlSigKeyInfoKeyNameTransformer()
                        .getKeyName(keys.getKid(), keys.getCertificate());
                binding.signWith(keyName, keys.getPrivateKey(), keys.getPublicKey(), keys.getCertificate())
                        .signatureAlgorithm(getSignatureAlgorithm())
                        .signDocument();
                if (!postBinding && getConfig().isAddExtensionsElementWithKeyInfo()) {
                    authnRequestBuilder.addExtension(new KeycloakKeySamlExtensionGenerator(keyName));
                }
            }

            AuthnRequestType authnRequest = authnRequestBuilder.createAuthnRequest();
            for (Iterator<SamlAuthenticationPreprocessor> it =
                            SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session);
                    it.hasNext(); ) {
                authnRequest = it.next().beforeSendingLoginRequest(authnRequest, authSession);
            }

            if (authnRequest.getDestination() != null) {
                destinationUrl = authnRequest.getDestination().toString();
            }

            // Save the request ID in auth session for later validation
            authSession.setClientNote(
                    org.keycloak.protocol.saml.SamlProtocol.SAML_REQUEST_ID_BROKER, authnRequest.getID());

            if (postBinding) {
                return binding.postBinding(SAML2Request.convert(authnRequest)).request(destinationUrl);
            } else {
                return binding.redirectBinding(SAML2Request.convert(authnRequest))
                        .request(destinationUrl);
            }

        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    @Override
    public SignatureAlgorithm getSignatureAlgorithm() {
        String alg = getConfig().getSignatureAlgorithm();
        if (alg != null) {
            return SignatureAlgorithm.valueOf(alg);
        }
        return SignatureAlgorithm.RSA_SHA256;
    }

    private List<String> getAuthnContextClassRefUris() {
        String authnContextClassRefs = getConfig().getAuthnContextClassRefs();
        if (authnContextClassRefs == null || authnContextClassRefs.isEmpty()) {
            return new LinkedList<>();
        }
        List<String> result = new LinkedList<>();
        for (String ref : authnContextClassRefs.split(",")) {
            ref = ref.trim();
            if (!ref.isEmpty()) {
                result.add(ref);
            }
        }
        return result;
    }

    private List<String> getAuthnContextDeclRefUris() {
        String authnContextDeclRefs = getConfig().getAuthnContextDeclRefs();
        if (authnContextDeclRefs == null || authnContextDeclRefs.isEmpty()) {
            return new LinkedList<>();
        }
        List<String> result = new LinkedList<>();
        for (String ref : authnContextDeclRefs.split(",")) {
            ref = ref.trim();
            if (!ref.isEmpty()) {
                result.add(ref);
            }
        }
        return result;
    }

    public String getEntityId(UriInfo uriInfo, RealmModel realm) {
        String configEntityId = getConfig().getEntityId();
        if (configEntityId == null || configEntityId.isEmpty()) {
            return uriInfo.getBaseUriBuilder()
                    .path("realms")
                    .path(realm.getName())
                    .build()
                    .toString();
        }
        return configEntityId;
    }
}
