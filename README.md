# Keycloak Cookieless IDP Extension

Cookieless OIDC and SAML Identity Providers for Keycloak that enable IDP broker flows without relying on browser cookies.

## The Problem

Keycloak's standard OIDC and SAML Identity Providers rely on the `AUTH_SESSION_ID` cookie to recover the authentication session when the external IDP redirects back. This fails in several scenarios:

- **Native app handoff**: The external IDP opens a native app for authentication, which then opens a *new* browser instance to return the callback
- **Browser privacy settings**: Cookies are blocked by strict privacy settings or browser extensions
- **Cross-origin restrictions**: Third-party cookie restrictions prevent the cookie from being sent

When cookies are unavailable, Keycloak fails with an `identity_provider_missing_state` error because it cannot find the original authentication session.

## The Solution

This extension provides drop-in replacements for the standard OIDC and SAML Identity Providers that embed the session ID directly in the OAuth2 `state` parameter (OIDC) or SAML `RelayState` (SAML). The session can then be recovered on callback without relying on cookies.

### How It Works

```
Standard Flow (Cookie-Based):
1. Auth session created → AUTH_SESSION_ID cookie set
2. State = code.tabId.clientId (NO session ID)
3. Callback → Read cookie → Find session
4. If no cookie → ERROR: identity_provider_missing_state

Cookieless Flow:
1. Auth session created (cookie optional)
2. State = HMAC(sessionId).code.tabId.clientId (INCLUDES session ID)
3. Callback → Extract sessionId from state → Direct lookup
4. Works with or without cookies
```

### Security

The session ID embedded in the state parameter is protected by HMAC-SHA256 signing using a realm-specific secret key. This prevents:

- **Session ID tampering**: Any modification invalidates the signature
- **Session ID guessing**: Attackers cannot forge valid signed states
- **Cross-realm attacks**: Each realm uses its own signing key

## Installation

### Download

Download the latest JAR from the [Releases](https://github.com/dominikschlosser/keycloak-cookieless-idp-extension/releases) page.

### Deploy to Keycloak

Copy the JAR file to Keycloak's `providers` directory:

```bash
cp keycloak-cookieless-idp-extension-1.0.0.jar /opt/keycloak/providers/
```

Restart Keycloak or run the build command:

```bash
/opt/keycloak/bin/kc.sh build
```

## Configuration

### OIDC Identity Provider

1. In Keycloak Admin Console, go to **Identity Providers**
2. Click **Add provider** and select **Cookieless OpenID Connect v1.0**
3. Configure as you would a standard OIDC Identity Provider:
   - **Authorization URL**: The external IDP's authorization endpoint
   - **Token URL**: The external IDP's token endpoint
   - **Client ID**: Your client ID at the external IDP
   - **Client Secret**: Your client secret

All standard OIDC IDP options are supported.

### SAML Identity Provider

1. In Keycloak Admin Console, go to **Identity Providers**
2. Click **Add provider** and select **Cookieless SAML v2.0**
3. Configure as you would a standard SAML Identity Provider:
   - **Single Sign-On Service URL**: The external IDP's SSO endpoint
   - **Single Logout Service URL**: The external IDP's SLO endpoint (optional)
   - Import or configure the IDP's signing certificate

All standard SAML IDP options are supported.

> **Note**: The SAML provider uses the RelayState parameter to store session information. This means RelayState cannot be used for other purposes when using the cookieless SAML IDP.

## Provider IDs

| Provider | Provider ID |
|----------|-------------|
| Cookieless OIDC | `cookieless-oidc` |
| Cookieless SAML | `cookieless-saml` |

These can be used when configuring IDPs via the Admin REST API or realm import/export.

## Compatibility

| Keycloak Version | Extension Version |
|------------------|-------------------|
| 26.x             | 1.0.x             |

## Building from Source

### Prerequisites

- Java 17 or higher
- Maven 3.8 or higher
- Docker (for integration tests)

### Build

```bash
# Build without tests
mvn clean package -DskipTests

# Build with unit tests only
mvn clean package

# Build with integration tests (requires Docker)
mvn clean verify
```

The JAR file will be created at `target/keycloak-cookieless-idp-extension-1.0.0-SNAPSHOT.jar`.

## Technical Details

### OIDC State Format

The OIDC provider uses a URL-safe Base64-encoded state containing:
- Session ID (UUID)
- HMAC-SHA256 signature (truncated)
- Original state data (code, tabId, clientId, clientData)

No size limit applies to OAuth2 state parameters.

### SAML RelayState Format

SAML RelayState has an 80-byte limit. The provider uses a compact binary encoding:

```
[sessionId:16][hmac:8][clientId:16][tabId:4][code:8] = 52 bytes → 70 chars Base64Url
```

This fits within the 80-byte limit while including all necessary data for session recovery.

## License

Apache License, Version 2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Developer Certificate of Origin (DCO)

This project requires all commits to be signed off according to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This certifies that you have the right to submit the code under the project's license.

Sign off your commits using:

```bash
git commit -s -m "Your commit message"
```

Or add the sign-off manually:

```
Your commit message

Signed-off-by: Your Name <your.email@example.com>
```

### Code Formatting

This project uses [Spotless](https://github.com/diffplug/spotless) with Palantir Java Format for code formatting. Before submitting a PR, ensure your code is properly formatted:

```bash
# Check formatting
mvn spotless:check

# Apply formatting automatically
mvn spotless:apply
```
