package ru.yandex.practicum.oauth0.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import ru.yandex.practicum.oauth0.common.dto.TokenClaims;

public final class TokenCoder {
    private static final String ALGORITHM = "HS256";

    private final JsonMapper json = JsonMapper.builder()
                    .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY)
                    .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .build();
    private final byte[] secret;
    private final String issuer;
    private final long skew;
    private final Clock clock;

    public TokenCoder(String secret, String issuer, long skew, Clock clock) {
        if (secret == null) {
            throw new IllegalArgumentException("HS256 secret is required");
        }
        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (secretBytes.length < 32) {
            throw new IllegalArgumentException("HS256 secret must be at least 32 bytes");
        }
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("Issuer is required");
        }
        if (skew < 0 || skew > 300) {
            throw new IllegalArgumentException("Clock skew must be between 0 and 300 seconds");
        }
        if (clock == null) {
            throw new IllegalArgumentException("Clock is required");
        }
        this.secret = secretBytes;
        this.issuer = issuer;
        this.skew = skew;
        this.clock = clock;
    }

    public String encode(TokenClaims claims) {
        try {
            byte[] headerJson = json.writeValueAsBytes(Map.of("alg", ALGORITHM, "typ", "JWT"));
            byte[] payloadJson = json.writeValueAsBytes(claims);
            String header = encodeBase64Url(headerJson);
            String payload = encodeBase64Url(payloadJson);
            String content = header + "." + payload;
            String signature = encodeBase64Url(signHs256(content));
            return content + "." + signature;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot serialize token", e);
        }
    }

    public TokenClaims verify(String token, String type, String audience) {
        TokenClaims claims = decodeAndValidate(token);
        long now = clock.instant().getEpochSecond();
        if (!claims.getTyp().equals(type)
                || (audience != null && !audience.equals(claims.getAud()))
                || claims.getIat() > now + skew
                || claims.getExp() <= now - skew) {
            throw ApiException.invalidToken();
        }
        return claims;
    }

    public TokenClaims decodeAndValidate(String token) {
        try {
            String[] parts = token.split("\\.", -1);
            if (parts.length != 3) {
                throw ApiException.invalidToken();
            }
            for (String part : parts) {
                if (!part.matches("[A-Za-z0-9_-]+")) {
                    throw ApiException.invalidToken();
                }
            }
            byte[] signature = Base64.getUrlDecoder().decode(parts[2]);
            if (!MessageDigest.isEqual(signHs256(parts[0] + "." + parts[1]), signature)) {
                throw ApiException.invalidToken();
            }
            var header = json.readTree(Base64.getUrlDecoder().decode(parts[0]));
            if (header == null
                || !ALGORITHM.equals(header.path("alg").asText())
                || !"JWT".equals(header.path("typ").asText())) {
                throw ApiException.invalidToken();
            }
            TokenClaims claims = json.readValue(Base64.getUrlDecoder().decode(parts[1]), TokenClaims.class);
            validateClaims(claims);
            return claims;
        } catch (IOException | IllegalArgumentException e) {
            throw ApiException.invalidToken();
        }
    }

    private void validateClaims(TokenClaims claims) {
        if (claims == null) {
            throw ApiException.invalidToken();
        }
        boolean accessToken = "AT".equals(claims.getTyp());
        boolean refreshToken = "RT".equals(claims.getTyp());
        if ((!accessToken && !refreshToken) || !ALGORITHM.equals(claims.getAlg())) {
            throw ApiException.invalidToken();
        }
        if (!issuer.equals(claims.getIss()) || blank(claims.getAud())
            || blank(claims.getSub()) || blank(claims.getClientId())) {
            throw ApiException.invalidToken();
        }
        if (claims.getIat() <= 0 || claims.getExp() <= claims.getIat()) {
            throw ApiException.invalidToken();
        }
        if (invalidPermissions(claims.getScopes()) || invalidPermissions(claims.getRoles())) {
            throw ApiException.invalidToken();
        }
        if ((accessToken && blank(claims.getJti()))
                || (refreshToken && blank(claims.getRefreshId()))) {
            throw ApiException.invalidToken();
        }
    }

    private static boolean invalidPermissions(List<String> permissions) {
        return permissions == null || permissions.stream().anyMatch(TokenCoder::blank);
    }

    private static boolean blank(String s) {
        return s == null || s.isBlank();
    }

    private byte[] signHs256(String content) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(content.getBytes(StandardCharsets.US_ASCII));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot compute HS256 signature", e);
        }
    }

    private static String encodeBase64Url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
