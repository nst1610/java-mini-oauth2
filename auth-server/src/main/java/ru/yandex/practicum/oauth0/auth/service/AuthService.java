package ru.yandex.practicum.oauth0.auth.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.config.AuthProperties;
import ru.yandex.practicum.oauth0.auth.dto.RefreshRequest;
import ru.yandex.practicum.oauth0.auth.dto.TokenRequest;
import ru.yandex.practicum.oauth0.auth.dto.TokenResponse;
import ru.yandex.practicum.oauth0.auth.model.Client;
import ru.yandex.practicum.oauth0.auth.model.RefreshEntry;
import ru.yandex.practicum.oauth0.auth.model.User;
import ru.yandex.practicum.oauth0.auth.repository.AuthRepository;
import ru.yandex.practicum.oauth0.auth.util.PasswordUtil;
import ru.yandex.practicum.oauth0.common.ApiException;
import ru.yandex.practicum.oauth0.common.TokenCoder;
import ru.yandex.practicum.oauth0.common.dto.TokenClaims;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {
    private final AuthRepository repository;
    private final TokenCoder coder;
    private final AuthProperties properties;
    private final Clock clock;
    private final ObjectMapper objectMapper;

    @Transactional
    public TokenResponse token(TokenRequest request) {
        required(request.getGrantType());
        if (!Set.of("password", "client_credentials").contains(request.getGrantType())) {
            throw new ApiException(400, "unsupported_grant_type", "Unknown grant_type");
        }
        Client client = authenticate(request.getClientId(), request.getClientSecret(), request.getGrantType());
        User user = null;
        if ("password".equals(request.getGrantType())) {
            required(request.getUsername());
            required(request.getPassword());
            user = repository.getUserByName(request.getUsername());
            if (user == null || !PasswordUtil.matches(request.getPassword(), user.getPasswordHash())) {
                throw invalidCredentials();
            }
            checkUser(user);
        }
        List<String> allowed = allowed(client, user);
        return issue(client, user, selectScopes(request.getScopes(), allowed));
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest request) {
        if (request.getGrantType() != null && !"refresh_token".equals(request.getGrantType())) {
            throw new ApiException(400, "unsupported_grant_type", "Expected refresh_token grant");
        }
        Client client = authenticate(request.getClientId(), request.getClientSecret(), "refresh_token");
        TokenClaims claims = coder.verify(request.getRefreshToken(), "RT", client.getAudience());
        if (!client.getId().equals(claims.getClientId())) {
            throw ApiException.invalidToken();
        }
        RefreshEntry entry = repository.getRefresh(claims.getRefreshId());
        if (entry == null
                || !entry.getClientId().equals(client.getId())
                || !entry.getUserId().equals(claims.getSub())
                || entry.getExp() != claims.getExp()
                || entry.getExp() <= now()
                || repository.revoked("refresh", entry.getId())) {
            throw ApiException.invalidToken();
        }
        if (entry.isRotated()) {
            throw new ApiException(409, "refresh_reused", "Refresh token has already been rotated");
        }
        User user = repository.getUser(entry.getUserId());
        checkUser(user);
        List<String> scopes = new ArrayList<>(repository.getRefreshScopes(entry.getId()));
        scopes.retainAll(allowed(client, user));
        repository.markRotated(entry.getId());
        TokenResponse response = issue(client, user, scopes);
        log.info("Refresh rotated successfully");
        return response;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> introspect(String token) {
        try {
            TokenClaims claims = coder.verify(token, "AT", null);
            if (repository.revoked("access", claims.getJti())) {
                return Map.of("active", false);
            }
            Client client = repository.getClient(claims.getClientId());
            if (client == null || !client.getAudience().equals(claims.getAud())) {
                return Map.of("active", false);
            }
            boolean serviceToken =
                    claims.getSub().equals(claims.getClientId()) && claims.getRoles().isEmpty();
            User user = serviceToken ? null : repository.getUser(claims.getSub());
            if (!serviceToken && user == null) {
                return Map.of("active", false);
            }
            if (user != null
                    && (user.isBlocked()
                            || !repository.getRoles(user.getId()).containsAll(claims.getRoles()))) {
                return Map.of("active", false);
            }
            if (!allowed(client, user).containsAll(claims.getScopes())) {
                return Map.of("active", false);
            }
            Map<String, Object> result =
                    objectMapper.convertValue(claims, new TypeReference<Map<String, Object>>() {});
            result.put("active", true);
            return result;
        } catch (ApiException e) {
            return Map.of("active", false);
        }
    }

    @Transactional
    public void revoke(String token, String hint) {
        if (hint != null && !Set.of("access_token", "refresh_token").contains(hint)) {
            throw new ApiException(400, "invalid_request", "Unknown token_type_hint");
        }
        TokenClaims claims;
        try {
            claims = coder.decodeAndValidate(token);
        } catch (ApiException e) {
            return;
        }
        if ("AT".equals(claims.getTyp())) {
            repository.revoke("access", claims.getJti(), claims.getExp());
        } else {
            RefreshEntry entry = repository.getRefresh(claims.getRefreshId());
            if (entry != null) {
                repository.revoke("refresh", entry.getId(), entry.getExp());
            }
        }
        log.info("Token revoked: type={}", claims.getTyp());
    }

    private TokenResponse issue(Client client, User user, List<String> scopes) {
        long issued = now();
        String subject = user == null ? client.getId() : user.getId();
        List<String> roles = user == null ? List.of() : repository.getRoles(user.getId());
        Map<String, Object> info = info(user == null ? client.getInfo() : user.getInfo());
        String access = coder.encode(
            new TokenClaims(
                "AT",
                "HS256",
                properties.getIssuer(),
                client.getAudience(),
                subject,
                client.getId(),
                scopes,
                roles,
                info,
                issued,
                issued + properties.getAccessTtlSec(),
                UUID.randomUUID().toString(),
                null
            )
        );
        String refresh = null;
        if (user != null) {
            String id = UUID.randomUUID().toString();
            long exp = issued + Duration.ofDays(properties.getRefreshTtlDays()).toSeconds();
            refresh = coder.encode(
                new TokenClaims(
                    "RT",
                    "HS256",
                    properties.getIssuer(),
                    client.getAudience(),
                    subject,
                    client.getId(),
                    scopes,
                    roles,
                    Map.of(),
                    issued,
                    exp,
                    null,
                    id
                )
            );
            repository.saveRefresh(new RefreshEntry(id, user.getId(), client.getId(), exp, false), scopes);
        }
        log.info("Token issued: flow={}", user == null ? "client_credentials" : "user");
        return new TokenResponse(access, "Bearer", properties.getAccessTtlSec(), refresh, scopes);
    }

    private Client authenticate(String id, String secret, String grant) {
        required(id);
        required(secret);
        Client client = repository.getClient(id);
        if (client == null || !PasswordUtil.matches(secret, client.getSecretHash())) {
            throw invalidCredentials();
        }
        if (!repository.getGrants(id).contains(grant)) {
            throw new ApiException(403, "unauthorized_client", "Grant is not allowed for this client");
        }
        return client;
    }

    private List<String> allowed(Client client, User user) {
        List<String> scopes = new ArrayList<>(repository.getClientScopes(client.getId()));
        if (user != null) {
            scopes.retainAll(repository.getUserScopes(user.getId()));
        }
        return scopes;
    }

    private List<String> selectScopes(List<String> requested, List<String> allowed) {
        if (requested == null) {
            return List.copyOf(allowed);
        }
        if (!allowed.containsAll(requested)) {
            throw new ApiException(403, "invalid_scope", "Requested scopes are not allowed");
        }
        return requested.stream().distinct().sorted().toList();
    }

    private void checkUser(User user) {
        if (user == null) {
            throw ApiException.invalidToken();
        }
        if (user.isBlocked()) {
            throw new ApiException(403, "user_blocked", "User is blocked");
        }
    }

    private static void required(String value) {
        if (value == null || value.isBlank()) {
            throw new ApiException(400, "invalid_request", "Required parameter is missing");
        }
    }

    private ApiException invalidCredentials() {
        return new ApiException(401, "invalid_credentials", "Invalid credentials");
    }

    private long now() {
        return clock.instant().getEpochSecond();
    }

    private Map<String, Object> info(String value) {
        try {
            if (value == null) {
                throw new IllegalStateException("Stored info must be a JSON object");
            }
            Map<String, Object> result = objectMapper.readValue(value, new TypeReference<Map<String, Object>>() {});
            if (result == null) {
                throw new IllegalStateException("Stored info must be a JSON object");
            }
            return result;
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Invalid info JSON in database", e);
        }
    }
}
