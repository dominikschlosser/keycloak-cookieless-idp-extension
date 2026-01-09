# Keycloak Cookieless IDP Extension

## Project Overview

This extension provides cookieless versions of OIDC and SAML Identity Providers for Keycloak. The standard IDP implementations rely on the `AUTH_SESSION_ID` cookie to recover the authentication session when the external IDP redirects back. This fails when:
- The external IDP opens a native app that returns in a new browser instance
- Cookies are blocked by browser privacy settings
- Cross-origin scenarios where cookies aren't sent

## Solution Architecture

### How It Works

The solution embeds the authentication session ID directly in the state parameter (OIDC) or RelayState (SAML), enabling stateless session recovery on callback without relying on cookies.

**Standard Flow (Cookie-Based):**
```
1. Auth session created → AUTH_SESSION_ID cookie set
2. State = code.tabId.clientId.clientData (NO session ID)
3. Callback → Read cookie → Find session → Verify code
```

**Cookieless Flow:**
```
1. Auth session created (cookie optional)
2. State = signedSessionId.code.tabId.clientId.clientData (INCLUDES session ID)
3. Callback → Extract sessionId from state → Direct lookup → Verify code
```

### Security

- Session ID is HMAC-signed to prevent tampering
- Uses realm's HMAC secret key for signing
- Falls back to standard cookie-based lookup if cookieless decoding fails

## Key Components

### OIDC Implementation

- **`CookielessOIDCIdentityProvider`** (`src/main/java/com/github/dominikschlosser/keycloak/broker/oidc/`)
  - Extends `OIDCIdentityProvider`
  - Overrides `createAuthorizationUrl()` to embed session ID in state
  - Custom `CookielessEndpoint` inner class handles callback with cookieless session lookup

- **`CookielessOIDCIdentityProviderFactory`**
  - Provider ID: `cookieless-oidc`
  - Displayed name: "Cookieless OpenID Connect v1.0"

### SAML Implementation

- **`CookielessSAMLIdentityProvider`** (`src/main/java/com/github/dominikschlosser/keycloak/broker/saml/`)
  - Extends `SAMLIdentityProvider`
  - Overrides `performLogin()` to embed session ID in RelayState
  - Uses compact binary encoding to fit within SAML 80-byte RelayState limit

- **`CookielessSAMLEndpoint`**
  - Wraps the callback to intercept `getAndVerifyAuthenticationSession()`
  - Attempts cookieless decoding first, falls back to standard callback

- **`CookielessSAMLIdentityProviderFactory`**
  - Provider ID: `cookieless-saml`
  - Displayed name: "Cookieless SAML v2.0"

### Shared Components

- **`CookielessIdentityBrokerState`** (`src/main/java/com/github/dominikschlosser/keycloak/broker/`)
  - Handles state encoding/decoding for both OIDC and SAML
  - OIDC format: JSON-based (no size limit)
  - SAML format: Compact binary (52 bytes → 70 chars Base64Url)

## SAML RelayState Encoding (80-byte limit)

**IMPORTANT:** The RelayState is fully consumed by this extension. It cannot be used for other purposes when using the cookieless SAML IDP.

**Compact Binary Format:**
```
[sessionId:16][hmac:8][clientId:16][tabId:4][code:8] = 52 bytes → 70 chars Base64Url
```

Field specifications:
- Session ID: 16 bytes raw UUID binary (root auth session ID)
- HMAC-SHA256 truncated: 8 bytes (64-bit security)
- ClientId: 16 bytes raw UUID binary (client DB ID)
- TabId: 4 bytes (first 4 bytes of SHA-256 hash)
- Code: 8 bytes (shortened authorization code)

## Building

```bash
# Build without tests
mvn clean package -DskipTests

# Run unit tests
mvn test

# Run all tests including integration tests
mvn verify
```

## Deployment

Copy the JAR to Keycloak's providers directory:
```bash
cp target/keycloak-cookieless-idp-extension-1.0.0-SNAPSHOT.jar /opt/keycloak/providers/
```

Then rebuild Keycloak:
```bash
/opt/keycloak/bin/kc.sh build
```

## Configuration

In Keycloak Admin Console:
1. Go to Identity Providers
2. Add provider → Select "Cookieless OpenID Connect v1.0" or "Cookieless SAML v2.0"
3. Configure as you would a standard OIDC/SAML IDP

## Dependencies

- Keycloak 26.5.0 (compile-time dependency, provided at runtime)
- Jakarta EE 10

## Testing

### Integration Tests

Located in `src/test/java/com/github/dominikschlosser/keycloak/e2e/`:
- `CookielessOIDCIdpIT` - Tests OIDC cookieless flow

Uses Testcontainers to spin up a Keycloak instance with the extension loaded.

### Mock OIDC Server

`src/test/java/com/github/dominikschlosser/keycloak/mock/MockOIDCServer.java` provides a simple OIDC server for testing purposes with endpoints:
- `/.well-known/openid-configuration`
- `/authorize`
- `/token`
- `/jwks`
- `/userinfo`

## Project Structure

```
src/
├── main/java/com/github/dominikschlosser/keycloak/
│   └── broker/
│       ├── CookielessIdentityBrokerState.java
│       ├── oidc/
│       │   ├── CookielessOIDCIdentityProvider.java
│       │   └── CookielessOIDCIdentityProviderFactory.java
│       └── saml/
│           ├── CookielessSAMLIdentityProvider.java
│           ├── CookielessSAMLIdentityProviderFactory.java
│           └── CookielessSAMLEndpoint.java
└── test/java/com/github/dominikschlosser/keycloak/
    ├── e2e/
    │   └── CookielessOIDCIdpIT.java
    └── mock/
        └── MockOIDCServer.java
```

## License

Apache License, Version 2.0
