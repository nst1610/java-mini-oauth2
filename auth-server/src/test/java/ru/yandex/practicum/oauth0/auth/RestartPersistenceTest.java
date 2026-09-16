package ru.yandex.practicum.oauth0.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;

import ru.yandex.practicum.oauth0.auth.dto.RefreshRequest;
import ru.yandex.practicum.oauth0.auth.dto.TokenRequest;
import ru.yandex.practicum.oauth0.auth.dto.TokenResponse;
import ru.yandex.practicum.oauth0.auth.service.AuthService;
import ru.yandex.practicum.oauth0.common.ApiException;

import java.nio.file.Path;

class RestartPersistenceTest {
    @TempDir
    private Path directory;

    private ConfigurableApplicationContext start() {
        return new SpringApplicationBuilder(AuthApp.class)
                .web(WebApplicationType.NONE)
                .run(
                        "--spring.datasource.url=jdbc:h2:file:"
                                + directory.resolve("auth")
                                + ";DB_CLOSE_ON_EXIT=FALSE",
                        "--logging.file.name=target/test-restart.log",
                        "--spring.main.banner-mode=off");
    }

    private RefreshRequest refresh(String token) {
        return new RefreshRequest("cli-001", "secret", token, null);
    }

    @Test
    void restartPreservesRevocationRotationValidSessionsAndUserChanges() {
        TokenResponse original, rotated, revokedRefresh;
        try (var context = start()) {
            assertEquals(
                    0,
                    context.getBean(JdbcTemplate.class)
                            .queryForObject("SELECT COUNT(*) FROM users", Integer.class));
            // Seed only the first startup. The second must use the persisted state as-is.
            new ResourceDatabasePopulator(new ClassPathResource("fixtures/auth-data.sql"))
                    .execute(context.getBean(DataSource.class));
            AuthService service = context.getBean(AuthService.class);
            var request =
                    new TokenRequest("password", "cli-001", "secret", "alice", "pass", null);
            original = service.token(request);
            rotated = service.refresh(refresh(original.getRefreshToken()));
            revokedRefresh = service.token(request);
            service.revoke(original.getAccessToken(), null);
            service.revoke(revokedRefresh.getRefreshToken(), null);
            context.getBean(JdbcTemplate.class)
                    .update("UPDATE users SET blocked=TRUE WHERE username='bob'");
        }
        try (var context = start()) {
            AuthService service = context.getBean(AuthService.class);
            assertEquals(false, service.introspect(original.getAccessToken()).get("active"));
            assertEquals(true, service.introspect(rotated.getAccessToken()).get("active"));
            assertEquals(
                    409,
                    assertThrows(
                                    ApiException.class,
                                    () -> service.refresh(refresh(original.getRefreshToken())))
                            .getStatus());
            assertEquals(
                    401,
                    assertThrows(
                                    ApiException.class,
                                    () ->
                                            service.refresh(
                                                    refresh(revokedRefresh.getRefreshToken())))
                            .getStatus());
            assertNotNull(service.refresh(refresh(rotated.getRefreshToken())).getRefreshToken());
            assertTrue(
                    context.getBean(JdbcTemplate.class)
                            .queryForObject(
                                    "SELECT blocked FROM users WHERE username='bob'",
                                    Boolean.class));
        }
    }
}
