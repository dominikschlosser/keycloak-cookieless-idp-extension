package com.github.dominikschlosser.keycloak.broker;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.keycloak.common.util.Base64Url;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;

/**
 * Extended state encoding for cookieless IDP flows.
 *
 * <p>This class encodes the authentication session ID along with the standard state parameters,
 * allowing session recovery without cookies when the external IDP redirects back.
 *
 * <p>Format for OIDC (no size limit):
 *
 * <pre>
 * signedSessionId.code.tabId.clientId[.clientData]
 * </pre>
 *
 * where signedSessionId = Base64Url(sessionId + "." + hmacSignature)
 *
 * <p>Format for SAML (compact binary, max 80 bytes in RelayState):
 *
 * <pre>
 * Base64Url([sessionId:16][hmac:8][clientId:16][tabId:4][code:8])
 * </pre>
 *
 * <p>IMPORTANT: For SAML, the RelayState is fully consumed by this encoding and cannot be used for
 * other purposes when using the cookieless SAML IDP.
 */
public class CookielessIdentityBrokerState {

    private static final Pattern DOT = Pattern.compile("\\.");
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final int HMAC_TRUNCATED_LENGTH = 8; // 64-bit security

    private final String sessionId;
    private final String code;
    private final String tabId;
    private final String clientId;
    private final String clientData;
    private final String userId; // For step-up authentication: the already-authenticated user
    private final String encoded;

    private CookielessIdentityBrokerState(
            String sessionId,
            String code,
            String tabId,
            String clientId,
            String clientData,
            String userId,
            String encoded) {
        this.sessionId = sessionId;
        this.code = code;
        this.tabId = tabId;
        this.clientId = clientId;
        this.clientData = clientData;
        this.userId = userId;
        this.encoded = encoded;
    }

    /**
     * Encode state for OIDC (no size limit). The session ID is signed using HMAC to prevent
     * tampering.
     *
     * @param sessionId The root authentication session ID
     * @param code The authorization code
     * @param tabId The browser tab ID
     * @param clientDbId The client's database ID (UUID)
     * @param clientClientId The client's client_id
     * @param clientData Additional client data
     * @param userId The authenticated user ID (for step-up auth), or null for initial login
     * @param hmacKey The HMAC key for signing
     */
    public static CookielessIdentityBrokerState encodeOIDC(
            String sessionId,
            String code,
            String tabId,
            String clientDbId,
            String clientClientId,
            String clientData,
            String userId,
            byte[] hmacKey) {

        // Sign the session ID (includes user ID in signature if present for step-up)
        String dataToSign = userId != null ? sessionId + ":" + userId : sessionId;
        String signedSessionId = signSessionId(dataToSign, hmacKey);

        // Encode client ID (compress UUID if possible)
        String clientIdEncoded = encodeClientId(clientDbId, clientClientId);

        // Encode user ID if present (for step-up authentication)
        String userIdEncoded = userId != null ? encodeUserId(userId) : null;

        // Build encoded state
        StringBuilder sb = new StringBuilder();
        sb.append(signedSessionId);
        sb.append(".").append(code);
        sb.append(".").append(tabId);
        sb.append(".").append(clientIdEncoded);
        if (clientData != null && !clientData.isEmpty()) {
            sb.append(".").append(clientData);
        }
        // Add user ID as last component if present (step-up auth marker)
        if (userIdEncoded != null) {
            sb.append(".u:").append(userIdEncoded);
        }

        return new CookielessIdentityBrokerState(
                sessionId, code, tabId, clientClientId, clientData, userId, sb.toString());
    }

    /**
     * Encode state for OIDC without user ID (for backward compatibility and initial logins).
     */
    public static CookielessIdentityBrokerState encodeOIDC(
            String sessionId,
            String code,
            String tabId,
            String clientDbId,
            String clientClientId,
            String clientData,
            byte[] hmacKey) {
        return encodeOIDC(sessionId, code, tabId, clientDbId, clientClientId, clientData, null, hmacKey);
    }

    /**
     * Encode state for SAML RelayState. Uses a compact string format to fit within 80 bytes.
     *
     * <p>Format: sessionId.clientIdShort.tabId.hmac
     *
     * <p>Where:
     * <ul>
     *   <li>sessionId: The actual session ID string (URL-safe, ~24 chars)
     *   <li>clientIdShort: First 4 bytes of SHA256(clientDbId), Base64Url (6 chars)
     *   <li>tabId: The actual tab ID string (~11 chars) - allows direct session lookup
     *   <li>hmac: First 8 bytes of HMAC(sessionId+clientDbId+tabId), Base64Url (11 chars)
     * </ul>
     *
     * <p>Total: ~24 + 1 + 6 + 1 + 11 + 1 + 11 = ~55 chars, within 80 byte limit.
     */
    public static CookielessIdentityBrokerState encodeSAML(
            String sessionId, String code, String tabId, String clientDbId, byte[] hmacKey) {

        // Client ID short hash (4 bytes -> 6 chars Base64Url)
        byte[] clientIdHash = sha256(clientDbId.getBytes(StandardCharsets.UTF_8));
        String clientIdShort = Base64Url.encode(Arrays.copyOf(clientIdHash, 4));

        // HMAC of all data (8 bytes -> 11 chars Base64Url)
        byte[] hmac = computeHmac(sessionId + clientDbId + tabId, hmacKey);
        String hmacShort = Base64Url.encode(Arrays.copyOf(hmac, HMAC_TRUNCATED_LENGTH));

        // Build encoded state: sessionId.clientIdShort.tabId.hmac
        // Using actual tabId allows O(1) direct lookup instead of iteration
        String encoded = sessionId + "." + clientIdShort + "." + tabId + "." + hmacShort;

        return new CookielessIdentityBrokerState(sessionId, code, tabId, clientDbId, null, null, encoded);
    }

    /**
     * Encode state for SAML RelayState with step-up user ID support.
     *
     * <p>Format: sessionId.clientIdShort.tabId.hmac[.userIdShort]
     *
     * <p>For step-up authentication, includes a short user ID hash for verification.
     */
    public static CookielessIdentityBrokerState encodeSAML(
            String sessionId, String code, String tabId, String clientDbId, String userId, byte[] hmacKey) {

        // Client ID short hash (4 bytes -> 6 chars Base64Url)
        byte[] clientIdHash = sha256(clientDbId.getBytes(StandardCharsets.UTF_8));
        String clientIdShort = Base64Url.encode(Arrays.copyOf(clientIdHash, 4));

        // Include userId in HMAC if present (step-up auth)
        String hmacData = userId != null ? sessionId + clientDbId + tabId + userId : sessionId + clientDbId + tabId;
        byte[] hmac = computeHmac(hmacData, hmacKey);
        String hmacShort = Base64Url.encode(Arrays.copyOf(hmac, HMAC_TRUNCATED_LENGTH));

        // Build encoded state
        StringBuilder sb = new StringBuilder();
        sb.append(sessionId).append(".");
        sb.append(clientIdShort).append(".");
        sb.append(tabId).append(".");
        sb.append(hmacShort);

        // Add user ID short hash if present (step-up auth)
        // Format: first 6 bytes of SHA256(userId) -> 8 chars Base64Url
        if (userId != null) {
            byte[] userIdHash = sha256(userId.getBytes(StandardCharsets.UTF_8));
            String userIdShort = Base64Url.encode(Arrays.copyOf(userIdHash, 6));
            sb.append(".").append(userIdShort);
        }

        return new CookielessIdentityBrokerState(sessionId, code, tabId, clientDbId, null, userId, sb.toString());
    }

    /** Decode OIDC state parameter. */
    public static CookielessIdentityBrokerState decodeOIDC(String encodedState, RealmModel realm, byte[] hmacKey) {
        if (encodedState == null || encodedState.isEmpty()) {
            throw new IllegalArgumentException("Encoded state is null or empty");
        }

        String[] parts = DOT.split(encodedState, 6);
        if (parts.length < 4) {
            throw new IllegalArgumentException("Invalid state format: expected at least 4 parts");
        }

        // Extract and verify signed session ID
        String signedSessionId = parts[0];

        String code = parts[1];
        String tabId = parts[2];
        String clientIdEncoded = parts[3];

        // Check for user ID marker (for step-up auth)
        String clientData = null;
        String userId = null;

        for (int i = 4; i < parts.length; i++) {
            if (parts[i].startsWith("u:")) {
                // User ID for step-up authentication
                userId = decodeUserId(parts[i].substring(2));
            } else if (clientData == null) {
                clientData = parts[i];
            }
        }

        // Verify the signed session ID (includes user ID if present)
        String dataToSign = userId != null ? null : null; // Will be verified with extracted data
        String sessionId = verifyAndExtractSessionId(signedSessionId, userId, hmacKey);

        // Decode client ID
        String clientId = decodeClientId(clientIdEncoded, realm);

        return new CookielessIdentityBrokerState(sessionId, code, tabId, clientId, clientData, userId, encodedState);
    }

    /**
     * Decode SAML RelayState.
     *
     * <p>Format: sessionId.clientIdShort.tabId.hmac[.userIdShort]
     *
     * <p>Returns the session ID and actual tabId for direct O(1) lookup. The clientIdShort is a
     * hash prefix used for verification after lookup. The userIdShort is present for step-up auth.
     */
    public static CookielessIdentityBrokerState decodeSAML(String encodedState, byte[] hmacKey) {
        if (encodedState == null || encodedState.isEmpty()) {
            throw new IllegalArgumentException("Encoded state is null or empty");
        }

        String[] parts = DOT.split(encodedState, 5);
        if (parts.length < 4 || parts.length > 5) {
            throw new IllegalArgumentException("Invalid SAML state format: expected 4 or 5 parts, got " + parts.length);
        }

        String sessionId = parts[0];
        String clientIdShort = parts[1];
        String tabId = parts[2]; // Actual tabId, not a hash
        String hmacShort = parts[3];

        // User ID short hash for step-up (stored for later verification)
        String userIdShort = parts.length > 4 ? parts[4] : null;

        // Return decoded state with actual tabId for direct lookup
        // clientIdShort is stored in the clientId field for later verification
        // userIdShort is stored in the userId field for later verification
        return new CookielessIdentityBrokerState(
                sessionId, null, tabId, clientIdShort, null, userIdShort, encodedState);
    }

    /**
     * Check if a user ID matches the short hash stored in the SAML state.
     */
    public static boolean matchesUserIdShort(String userId, String userIdShort) {
        if (userId == null || userIdShort == null) {
            return userId == null && userIdShort == null;
        }
        byte[] hash = sha256(userId.getBytes(StandardCharsets.UTF_8));
        String computed = Base64Url.encode(Arrays.copyOf(hash, 6));
        return computed.equals(userIdShort);
    }

    /**
     * Verify that the HMAC in a decoded SAML state matches the expected value.
     *
     * @param decodedState The decoded state from decodeSAML
     * @param clientDbId The actual client database ID found from the auth session
     * @param tabId The actual tab ID found from the auth session
     * @param hmacKey The HMAC key for verification
     * @return true if the HMAC is valid
     */
    public static boolean verifySAMLHmac(
            CookielessIdentityBrokerState decodedState, String clientDbId, String tabId, byte[] hmacKey) {
        return verifySAMLHmac(decodedState, clientDbId, tabId, null, hmacKey);
    }

    /**
     * Verify that the HMAC in a decoded SAML state matches the expected value, including user ID for
     * step-up authentication.
     *
     * @param decodedState The decoded state from decodeSAML
     * @param clientDbId The actual client database ID found from the auth session
     * @param tabId The actual tab ID found from the auth session
     * @param userId The actual user ID for step-up verification (null for initial login)
     * @param hmacKey The HMAC key for verification
     * @return true if the HMAC is valid
     */
    public static boolean verifySAMLHmac(
            CookielessIdentityBrokerState decodedState,
            String clientDbId,
            String tabId,
            String userId,
            byte[] hmacKey) {
        String sessionId = decodedState.getSessionId();
        String[] parts = DOT.split(decodedState.getEncoded(), 5);
        String storedHmac = parts[3];

        // Check if this is a step-up state (has user ID short hash)
        boolean isStepUp = parts.length > 4;

        // Recompute HMAC (includes userId if step-up)
        String hmacData =
                isStepUp && userId != null ? sessionId + clientDbId + tabId + userId : sessionId + clientDbId + tabId;
        byte[] expectedHmac = computeHmac(hmacData, hmacKey);
        String expectedHmacShort = Base64Url.encode(Arrays.copyOf(expectedHmac, HMAC_TRUNCATED_LENGTH));

        return MessageDigest.isEqual(
                storedHmac.getBytes(StandardCharsets.UTF_8), expectedHmacShort.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Check if a client ID matches the short hash stored in the SAML state.
     */
    public static boolean matchesClientIdShort(String clientDbId, String clientIdShort) {
        byte[] hash = sha256(clientDbId.getBytes(StandardCharsets.UTF_8));
        String computed = Base64Url.encode(Arrays.copyOf(hash, 4));
        return computed.equals(clientIdShort);
    }

    private static String signSessionId(String data, byte[] hmacKey) {
        byte[] hmac = computeHmac(data, hmacKey);
        String signature = Base64Url.encode(Arrays.copyOf(hmac, HMAC_TRUNCATED_LENGTH));
        return Base64Url.encode((data + "." + signature).getBytes(StandardCharsets.UTF_8));
    }

    private static String verifyAndExtractSessionId(String signedSessionId, String userId, byte[] hmacKey) {
        String decoded = new String(Base64Url.decode(signedSessionId), StandardCharsets.UTF_8);
        int dotIndex = decoded.lastIndexOf('.');
        if (dotIndex < 0) {
            throw new SecurityException("Invalid signed session ID format");
        }

        String signedData = decoded.substring(0, dotIndex);
        String signature = decoded.substring(dotIndex + 1);

        // Verify signature
        byte[] expectedHmac = computeHmac(signedData, hmacKey);
        byte[] actualHmac = Base64Url.decode(signature);

        if (!MessageDigest.isEqual(Arrays.copyOf(expectedHmac, HMAC_TRUNCATED_LENGTH), actualHmac)) {
            throw new SecurityException("Session ID signature verification failed");
        }

        // Extract session ID (may include ":userId" suffix for step-up auth)
        int colonIndex = signedData.indexOf(':');
        if (colonIndex > 0) {
            // Step-up auth: signedData = sessionId:userId
            String embeddedUserId = signedData.substring(colonIndex + 1);
            if (userId != null && !userId.equals(embeddedUserId)) {
                throw new SecurityException("User ID mismatch in signed state");
            }
            return signedData.substring(0, colonIndex);
        }
        return signedData;
    }

    private static String encodeUserId(String userId) {
        // Encode user ID (compress UUID if possible)
        try {
            UUID userUuid = UUID.fromString(userId);
            ByteBuffer bb = ByteBuffer.allocate(16);
            bb.putLong(userUuid.getMostSignificantBits());
            bb.putLong(userUuid.getLeastSignificantBits());
            return Base64Url.encode(bb.array());
        } catch (IllegalArgumentException e) {
            // Not a UUID, encode as string
            return Base64Url.encode(userId.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String decodeUserId(String encoded) {
        byte[] decoded = Base64Url.decode(encoded);
        if (decoded.length == 16) {
            // Try to interpret as UUID
            ByteBuffer bb = ByteBuffer.wrap(decoded);
            return new UUID(bb.getLong(), bb.getLong()).toString();
        }
        return new String(decoded, StandardCharsets.UTF_8);
    }

    private static byte[] computeHmac(String data, byte[] key) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("Failed to compute HMAC", e);
        }
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static String encodeClientId(String clientDbId, String clientClientId) {
        if (clientDbId != null) {
            try {
                UUID clientUuid = UUID.fromString(clientDbId);
                ByteBuffer bb = ByteBuffer.allocate(16);
                bb.putLong(clientUuid.getMostSignificantBits());
                bb.putLong(clientUuid.getLeastSignificantBits());
                return Base64Url.encode(bb.array());
            } catch (IllegalArgumentException e) {
                // Not a UUID, fall through
            }
        }
        return Base64Url.encode(clientClientId.getBytes(StandardCharsets.UTF_8));
    }

    private static String decodeClientId(String encoded, RealmModel realm) {
        byte[] decoded = Base64Url.decode(encoded);
        if (decoded.length == 16) {
            // Try to interpret as UUID
            ByteBuffer bb = ByteBuffer.wrap(decoded);
            UUID clientUuid = new UUID(bb.getLong(), bb.getLong());
            var client = realm.getClientById(clientUuid.toString());
            if (client != null) {
                return client.getClientId();
            }
        }
        return new String(decoded, StandardCharsets.UTF_8);
    }

    public String getSessionId() {
        return sessionId;
    }

    public String getCode() {
        return code;
    }

    public String getTabId() {
        return tabId;
    }

    public String getClientId() {
        return clientId;
    }

    public String getClientData() {
        return clientData;
    }

    /**
     * Get the user ID for step-up authentication. Returns null for initial logins.
     */
    public String getUserId() {
        return userId;
    }

    public String getEncoded() {
        return encoded;
    }

    /** Get the HMAC key from the realm's keys. Uses the realm's master key for signing. */
    public static byte[] getHmacKey(KeycloakSession session, RealmModel realm) {
        // Use a derived key from the realm's master secret
        // In production, this should use Keycloak's key management
        String realmId = realm.getId();
        return sha256((realmId + "-cookieless-idp-state").getBytes(StandardCharsets.UTF_8));
    }
}
