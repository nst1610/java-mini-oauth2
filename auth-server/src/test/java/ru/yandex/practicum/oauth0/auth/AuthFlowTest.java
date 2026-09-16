package ru.yandex.practicum.oauth0.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.web.servlet.MockMvc;

import ru.yandex.practicum.oauth0.common.TokenCoder;
import ru.yandex.practicum.oauth0.common.dto.TokenClaims;

import java.time.Clock;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@SpringBootTest(
        properties = {
            "spring.datasource.url=jdbc:h2:mem:flows;DB_CLOSE_DELAY=-1",
            "logging.file.name=target/test-auth.log"
        })
@Sql(scripts = {"/fixtures/cleanup.sql", "/fixtures/auth-data.sql"})
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
class AuthFlowTest {
    @Autowired
    private MockMvc mvc;

    @Autowired

    private ObjectMapper json;

    @Autowired

    private TokenCoder codec;

    @Autowired

    private Clock clock;

    @Autowired

    private JdbcTemplate jdbc;

    private Map<String, Object> password(String username) {
        return new HashMap<>(
                Map.of(
                        "grant_type", "password",
                        "username", username,
                        "password", "pass",
                        "client_id", "cli-001",
                        "client_secret", "secret"));
    }

    private JsonNode postJson(String path, Object data, int status) throws Exception {
        var result =
                mvc.perform(
                                post(path)
                                        .contentType(MediaType.APPLICATION_JSON)
                                        .content(json.writeValueAsBytes(data)))
                        .andExpect(status().is(status))
                        .andReturn();
        String body = result.getResponse().getContentAsString();
        return body.isBlank() ? json.nullNode() : json.readTree(body);
    }

    private Map<String, Object> refresh(String token) {
        return Map.of("refresh_token", token, "client_id", "cli-001", "client_secret", "secret");
    }

    @Test
    void passwordAndIntrospection() throws Exception {
        JsonNode pair = postJson("/token", password("alice"), 200);
        assertTrue(pair.hasNonNull("refresh_token"));
        assertEquals("Bearer", pair.path("token_type").asText());
        JsonNode active =
                postJson("/introspect", Map.of("token", pair.path("access_token").asText()), 200);
        assertTrue(active.path("active").asBoolean());
        assertEquals("u-100", active.path("sub").asText());
        assertEquals("viewer", active.path("roles").get(0).asText());
        assertEquals("payments:read", active.path("scopes").get(0).asText());
    }

    @Test
    void badCredentialsAndBlockedUser() throws Exception {
        var request = password("alice");
        request.put("password", "wrong");
        postJson("/token", request, 401);
        request = password("alice");
        request.put("client_secret", "wrong");
        postJson("/token", request, 401);
        postJson("/token", password("missing"), 401);
        postJson("/token", password("blocked"), 403);
    }

    @Test
    void clientCredentialsNoRefreshAndGrantRestriction() throws Exception {
        JsonNode token =
                postJson(
                        "/token",
                        Map.of(
                                "grant_type", "client_credentials",
                                "client_id", "service-001",
                                "client_secret", "secret"),
                        200);
        assertFalse(token.has("refresh_token"));
        JsonNode claims =
                postJson("/introspect", Map.of("token", token.path("access_token").asText()), 200);
        assertEquals("service-001", claims.path("sub").asText());
        assertTrue(claims.path("roles").isEmpty());
        var request = password("alice");
        request.put("client_id", "service-001");
        postJson("/token", request, 403);
    }

    @Test
    void viewerCannotRequestWriteAndUnknownScope() throws Exception {
        var request = password("alice");
        request.put("scopes", List.of("payments:write"));
        postJson("/token", request, 403);
        request = password("bob");
        request.put("scopes", List.of("unknown"));
        postJson("/token", request, 403);
        request.put("scopes", List.of("payments:write"));
        postJson("/token", request, 200);
    }

    @Test
    void rotationAndRefreshCannotBeIntrospectedAsAccess() throws Exception {
        JsonNode first = postJson("/token", password("alice"), 200);
        String old = first.path("refresh_token").asText();
        JsonNode next = postJson("/token/refresh", refresh(old), 200);
        assertNotEquals(old, next.path("refresh_token").asText());
        postJson("/token/refresh", refresh(old), 409);
        assertFalse(postJson("/introspect", Map.of("token", old), 200).path("active").asBoolean());
        postJson("/token/refresh", refresh(first.path("access_token").asText()), 401);
    }

    @Test
    void revokeAccessAndRefreshAndIdempotence() throws Exception {
        JsonNode pair = postJson("/token", password("alice"), 200);
        String access = pair.path("access_token").asText(),
                rt = pair.path("refresh_token").asText();
        postJson("/revoke", Map.of("token", access), 200);
        postJson("/revoke", Map.of("token", access), 200);
        assertFalse(
                postJson("/introspect", Map.of("token", access), 200).path("active").asBoolean());
        postJson("/revoke", Map.of("token", rt, "token_type_hint", "access_token"), 200);
        postJson("/token/refresh", refresh(rt), 401);
        postJson("/revoke", Map.of("token", "unknown"), 200);
    }

    @Test
    void refreshPreservesOriginalScopes() throws Exception {
        var request = password("bob");
        request.put("scopes", List.of("payments:read"));
        JsonNode pair = postJson("/token", request, 200);
        String refreshToken = pair.path("refresh_token").asText();

        var invalidRequest = new HashMap<>(refresh(refreshToken));
        invalidRequest.put("scopes", List.of("payments:write"));
        postJson("/token/refresh", invalidRequest, 400);

        JsonNode renewed = postJson("/token/refresh", refresh(refreshToken), 200);
        assertEquals(pair.path("scopes"), renewed.path("scopes"));
        JsonNode next =
                postJson("/token/refresh", refresh(renewed.path("refresh_token").asText()), 200);
        assertEquals(pair.path("scopes"), next.path("scopes"));
    }

    @Test
    void refreshMustBelongToClient() throws Exception {
        JsonNode pair = postJson("/token", password("alice"), 200);
        var request = new HashMap<>(refresh(pair.path("refresh_token").asText()));
        request.put("client_id", "service-001");
        postJson("/token/refresh", request, 403);
        jdbc.update(
                "INSERT INTO clients(client_id,client_secret_hash,aud,info) SELECT"
                        + " 'other',client_secret_hash,aud,info FROM clients WHERE"
                        + " client_id='cli-001'");
        jdbc.update(
                "INSERT INTO client_grants(client_id,grant_type) VALUES('other','refresh_token')");
        request.put("client_id", "other");
        postJson("/token/refresh", request, 401);
        postJson("/token/refresh", refresh(pair.path("refresh_token").asText()), 200);
    }

    private String signedToken(String type, long iat, long exp, String id) {
        TokenClaims claims =
                new TokenClaims(
                        type,
                        "HS256",
                        "mini-auth",
                        "payments-api",
                        "u-100",
                        "cli-001",
                        List.of("payments:read"),
                        List.of("viewer"),
                        Map.of(),
                        iat,
                        exp,
                        "AT".equals(type) ? id : null,
                        "RT".equals(type) ? id : null);
        return codec.encode(claims);
    }

    @Test
    void expiredAndEarlyAccessAreInactive() throws Exception {
        long now = clock.instant().getEpochSecond();
        for (String token :
                List.of(
                        signedToken("AT", now - 1000, now - 31, "expired"),
                        signedToken("AT", now + 120, now + 1000, "early"))) {
            assertFalse(
                    postJson("/introspect", Map.of("token", token), 200)
                            .path("active")
                            .asBoolean());
        }
    }

    @Test
    void refreshNeedsIndexAndDoesNotGetExpirySkew() throws Exception {
        long now = clock.instant().getEpochSecond();
        postJson(
                "/token/refresh", refresh(signedToken("RT", now - 100, now + 900, "missing")), 401);
        jdbc.update(
                "INSERT INTO refresh_index(refresh_id,user_id,client_id,exp,rotated) "
                        + "VALUES('expired','u-100','cli-001',?,FALSE)",
                now - 1);
        postJson("/token/refresh", refresh(signedToken("RT", now - 100, now - 1, "expired")), 401);
    }

    @Test
    void currentUserBlockAndRolePermissionsAreChecked() throws Exception {
        JsonNode pair = postJson("/token", password("alice"), 200);
        Map<String, String> token = Map.of("token", pair.path("access_token").asText());
        jdbc.update("UPDATE users SET blocked=TRUE WHERE user_id='u-100'");
        assertFalse(postJson("/introspect", token, 200).path("active").asBoolean());
        postJson("/token/refresh", refresh(pair.path("refresh_token").asText()), 403);
        jdbc.update("UPDATE users SET blocked=FALSE WHERE user_id='u-100'");
        jdbc.update(
                "DELETE FROM role_scopes WHERE role_id = (SELECT role_id FROM roles WHERE"
                    + " role_name='viewer')");
        assertFalse(postJson("/introspect", token, 200).path("active").asBoolean());
        assertTrue(
                postJson("/token/refresh", refresh(pair.path("refresh_token").asText()), 200)
                        .path("scopes")
                        .isEmpty());
    }

    @Test
    void malformedMissingAndUnsupportedRequests() throws Exception {
        postJson("/token", Map.of(), 400);
        var request = password("alice");
        request.put("grant_type", "unknown");
        postJson("/token", request, 400);
        request.put("grant_type", "refresh_token");
        assertEquals(
                "unsupported_grant_type", postJson("/token", request, 400).path("error").asText());
        request = password("alice");
        request.remove("password");
        postJson("/token", request, 400);
        request = password("alice");
        request.put("scopes", List.of(""));
        postJson("/token", request, 400);
        mvc.perform(post("/token").contentType(MediaType.APPLICATION_JSON).content("{broken"))
                .andExpect(status().isBadRequest());
        postJson("/token/refresh", Map.of("refresh_token", "bad"), 400);
        assertFalse(
                postJson("/introspect", Map.of("token", "a.b.c"), 200).path("active").asBoolean());
    }

    @Test
    void rejectedRequestsAreLoggedWithoutCredentialsOrTokens(CapturedOutput output)
            throws Exception {
        var request = password("alice");
        request.put("password", "log-password-marker");
        postJson("/token", request, 401);
        request = password("alice");
        request.put("client_secret", "log-getClient-secret-marker");
        postJson("/token", request, 401);
        request = password("alice");
        request.put("scopes", List.of("payments:write"));
        postJson("/token", request, 403);
        mvc.perform(
                        post("/token")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{broken-log-json-marker"))
                .andExpect(status().isBadRequest());
        var pair = postJson("/token", password("alice"), 200);
        String rt = pair.path("refresh_token").asText();
        postJson("/token/refresh", refresh(rt), 200);
        postJson("/token/refresh", refresh(rt), 409);
        assertThat(output.getAll())
                .contains(
                        "method=POST, path=/token, status=401, error=invalid_credentials",
                        "method=POST, path=/token, status=403, error=invalid_scope",
                        "method=POST, path=/token, status=400, error=invalid_request",
                        "method=POST, path=/token/refresh, status=409, error=refresh_reused")
                .doesNotContain(
                        "log-password-marker",
                        "log-getClient-secret-marker",
                        "broken-log-json-marker",
                        rt,
                        pair.path("access_token").asText());
    }

    @Test
    void removedRoleMakesAccessInactive() throws Exception {
        JsonNode pair = postJson("/token", password("alice"), 200);
        jdbc.update("DELETE FROM user_roles WHERE user_id='u-100'");
        assertFalse(
                postJson("/introspect", Map.of("token", pair.path("access_token").asText()), 200)
                        .path("active")
                        .asBoolean());
    }

    @Test
    void failedRefreshRollsBackRotationAndDoesNotLeakData(CapturedOutput output) throws Exception {
        JsonNode pair = postJson("/token", password("alice"), 200);
        String rt = pair.path("refresh_token").asText();
        jdbc.update("UPDATE users SET info=? WHERE user_id='u-100'", "{private-stored-marker");
        JsonNode error = postJson("/token/refresh", refresh(rt), 500);
        assertEquals("server_error", error.path("error").asText());
        assertThat(error.toString()).doesNotContain("private-stored-marker");
        assertThat(output.getAll()).contains("status=500").doesNotContain("private-stored-marker");
        jdbc.update("UPDATE users SET info='{}' WHERE user_id='u-100'");
        postJson("/token/refresh", refresh(rt), 200);
    }
}
