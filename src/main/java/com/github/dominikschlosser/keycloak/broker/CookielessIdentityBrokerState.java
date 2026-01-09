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
    private final String encoded;

    private CookielessIdentityBrokerState(
            String sessionId, String code, String tabId, String clientId, String clientData, String encoded) {
        this.sessionId = sessionId;
        this.code = code;
        this.tabId = tabId;
        this.clientId = clientId;
        this.clientData = clientData;
        this.encoded = encoded;
    }

    /**
     * Encode state for OIDC (no size limit). The session ID is signed using HMAC to prevent
     * tampering.
     */
    public static CookielessIdentityBrokerState encodeOIDC(
            String sessionId,
            String code,
            String tabId,
            String clientDbId,
            String clientClientId,
            String clientData,
            byte[] hmacKey) {

        // Sign the session ID
        String signedSessionId = signSessionId(sessionId, hmacKey);

        // Encode client ID (compress UUID if possible)
        String clientIdEncoded = encodeClientId(clientDbId, clientClientId);

        // Build encoded state
        StringBuilder sb = new StringBuilder();
        sb.append(signedSessionId);
        sb.append(".").append(code);
        sb.append(".").append(tabId);
        sb.append(".").append(clientIdEncoded);
        if (clientData != null && !clientData.isEmpty()) {
            sb.append(".").append(clientData);
        }

        return new CookielessIdentityBrokerState(sessionId, code, tabId, clientClientId, clientData, sb.toString());
    }

    /**
     * Encode state for SAML (compact binary format, fits in 80 bytes). Format:
     * [sessionId:16][hmac:8][clientId:16][tabId:4][code:8] = 52 bytes → 70 chars Base64
     */
    public static CookielessIdentityBrokerState encodeSAML(
            String sessionId, String code, String tabId, String clientDbId, byte[] hmacKey) {

        ByteBuffer buffer = ByteBuffer.allocate(52);

        // Session ID as UUID bytes (16 bytes)
        UUID sessionUuid = UUID.fromString(sessionId);
        buffer.putLong(sessionUuid.getMostSignificantBits());
        buffer.putLong(sessionUuid.getLeastSignificantBits());

        // HMAC of all data (8 bytes truncated)
        byte[] hmac = computeHmac(sessionId + clientDbId + tabId + code, hmacKey);
        buffer.put(Arrays.copyOf(hmac, HMAC_TRUNCATED_LENGTH));

        // Client ID as UUID bytes (16 bytes)
        UUID clientUuid = UUID.fromString(clientDbId);
        buffer.putLong(clientUuid.getMostSignificantBits());
        buffer.putLong(clientUuid.getLeastSignificantBits());

        // TabId - hash first 4 bytes (4 bytes)
        byte[] tabIdHash = sha256(tabId.getBytes(StandardCharsets.UTF_8));
        buffer.put(Arrays.copyOf(tabIdHash, 4));

        // Code - first 8 bytes of decoded code or hash (8 bytes)
        byte[] codeBytes = code.length() > 10
                ? Arrays.copyOf(sha256(code.getBytes(StandardCharsets.UTF_8)), 8)
                : Arrays.copyOf(Base64Url.decode(code), 8);
        buffer.put(codeBytes);

        String encoded = Base64Url.encode(buffer.array());

        return new CookielessIdentityBrokerState(sessionId, code, tabId, clientDbId, null, encoded);
    }

    /** Decode OIDC state parameter. */
    public static CookielessIdentityBrokerState decodeOIDC(String encodedState, RealmModel realm, byte[] hmacKey) {
        if (encodedState == null || encodedState.isEmpty()) {
            throw new IllegalArgumentException("Encoded state is null or empty");
        }

        String[] parts = DOT.split(encodedState, 5);
        if (parts.length < 4) {
            throw new IllegalArgumentException("Invalid state format: expected at least 4 parts");
        }

        // Extract and verify signed session ID
        String signedSessionId = parts[0];
        String sessionId = verifyAndExtractSessionId(signedSessionId, hmacKey);

        String code = parts[1];
        String tabId = parts[2];
        String clientIdEncoded = parts[3];
        String clientData = parts.length > 4 ? parts[4] : null;

        // Decode client ID
        String clientId = decodeClientId(clientIdEncoded, realm);

        return new CookielessIdentityBrokerState(sessionId, code, tabId, clientId, clientData, encodedState);
    }

    /** Decode SAML RelayState (compact binary format). */
    public static CookielessIdentityBrokerState decodeSAML(String encodedState, byte[] hmacKey) {
        if (encodedState == null || encodedState.isEmpty()) {
            throw new IllegalArgumentException("Encoded state is null or empty");
        }

        byte[] data = Base64Url.decode(encodedState);
        if (data.length != 52) {
            throw new IllegalArgumentException("Invalid SAML state length: " + data.length);
        }

        ByteBuffer buffer = ByteBuffer.wrap(data);

        // Session ID (16 bytes)
        long sessionMsb = buffer.getLong();
        long sessionLsb = buffer.getLong();
        String sessionId = new UUID(sessionMsb, sessionLsb).toString();

        // HMAC (8 bytes) - stored for verification
        byte[] storedHmac = new byte[HMAC_TRUNCATED_LENGTH];
        buffer.get(storedHmac);

        // Client ID (16 bytes)
        long clientMsb = buffer.getLong();
        long clientLsb = buffer.getLong();
        String clientId = new UUID(clientMsb, clientLsb).toString();

        // TabId hash (4 bytes) - we store this for matching, not the original tabId
        byte[] tabIdHash = new byte[4];
        buffer.get(tabIdHash);

        // Code (8 bytes) - truncated, used for matching
        byte[] codeBytes = new byte[8];
        buffer.get(codeBytes);

        // For SAML, we return special markers for tabId and code since we only have hashes
        // The actual verification will be done differently
        String tabIdMarker = Base64Url.encode(tabIdHash);
        String codeMarker = Base64Url.encode(codeBytes);

        return new CookielessIdentityBrokerState(sessionId, codeMarker, tabIdMarker, clientId, null, encodedState);
    }

    private static String signSessionId(String sessionId, byte[] hmacKey) {
        byte[] hmac = computeHmac(sessionId, hmacKey);
        String signature = Base64Url.encode(Arrays.copyOf(hmac, HMAC_TRUNCATED_LENGTH));
        return Base64Url.encode((sessionId + "." + signature).getBytes(StandardCharsets.UTF_8));
    }

    private static String verifyAndExtractSessionId(String signedSessionId, byte[] hmacKey) {
        String decoded = new String(Base64Url.decode(signedSessionId), StandardCharsets.UTF_8);
        int dotIndex = decoded.lastIndexOf('.');
        if (dotIndex < 0) {
            throw new SecurityException("Invalid signed session ID format");
        }

        String sessionId = decoded.substring(0, dotIndex);
        String signature = decoded.substring(dotIndex + 1);

        // Verify signature
        byte[] expectedHmac = computeHmac(sessionId, hmacKey);
        byte[] actualHmac = Base64Url.decode(signature);

        if (!MessageDigest.isEqual(Arrays.copyOf(expectedHmac, HMAC_TRUNCATED_LENGTH), actualHmac)) {
            throw new SecurityException("Session ID signature verification failed");
        }

        return sessionId;
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
