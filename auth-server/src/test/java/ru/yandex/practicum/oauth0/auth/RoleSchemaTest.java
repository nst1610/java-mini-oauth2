package ru.yandex.practicum.oauth0.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import java.util.UUID;

class RoleSchemaTest {

    @Test
    void roleIdsAreGeneratedAndNamesRemainUnique() {
        var dataSource = dataSource();
        new ResourceDatabasePopulator(new ClassPathResource("init.sql")).execute(dataSource);
        var jdbc = new JdbcTemplate(dataSource);

        jdbc.update("INSERT INTO roles(role_name) VALUES('viewer'), ('operator')");
        var ids = jdbc.queryForList("SELECT role_id FROM roles ORDER BY role_id", Long.class);

        assertThat(ids).hasSize(2);
        assertThat(ids.get(0)).isPositive();
        assertThat(ids.get(1)).isGreaterThan(ids.get(0));
        assertThrows(
                DataIntegrityViolationException.class,
                () -> jdbc.update("INSERT INTO roles(role_name) VALUES('viewer')"));
        assertThrows(
                DataIntegrityViolationException.class,
                () -> jdbc.update("INSERT INTO role_scopes(role_id, scope) VALUES(-1, 'read')"));
    }

    @Test
    void migrationPreservesExistingRolesAssignmentsAndScopes() {
        var dataSource = dataSource();
        var jdbc = new JdbcTemplate(dataSource);
        jdbc.execute("CREATE TABLE users(user_id VARCHAR(100) PRIMARY KEY)");
        jdbc.execute("CREATE TABLE roles(role_name VARCHAR(100) PRIMARY KEY)");
        jdbc.execute(
                """
                CREATE TABLE user_roles (
                    user_id VARCHAR(100) REFERENCES users(user_id),
                    role_name VARCHAR(100) REFERENCES roles(role_name),
                    PRIMARY KEY (user_id, role_name)
                )
                """);
        jdbc.execute(
                """
                CREATE TABLE role_scopes (
                    role_name VARCHAR(100) REFERENCES roles(role_name),
                    scope VARCHAR(200) NOT NULL,
                    PRIMARY KEY (role_name, scope)
                )
                """);
        jdbc.update("INSERT INTO users(user_id) VALUES('existing-user')");
        jdbc.update("INSERT INTO roles(role_name) VALUES('viewer'), ('operator'), ('unassigned')");
        jdbc.update(
                """
                INSERT INTO user_roles(user_id, role_name)
                VALUES('existing-user', 'viewer'), ('existing-user', 'operator')
                """);
        jdbc.update(
                """
                INSERT INTO role_scopes(role_name, scope)
                VALUES('viewer', 'payments:read'), ('operator', 'payments:read'),
                      ('operator', 'payments:write')
                """);

        new ResourceDatabasePopulator(new ClassPathResource("migrations/001-numeric-role-id.sql"))
                .execute(dataSource);
        // Normal startup must accept the migrated schema without modifying existing IDs.
        var ids = jdbc.queryForList("SELECT role_id FROM roles ORDER BY role_name", Long.class);
        new ResourceDatabasePopulator(new ClassPathResource("init.sql")).execute(dataSource);

        assertThat(
                        jdbc.queryForList(
                                "SELECT r.role_name FROM roles r JOIN user_roles ur ON r.role_id ="
                                    + " ur.role_id WHERE ur.user_id = 'existing-user' ORDER BY"
                                    + " r.role_name",
                                String.class))
                .containsExactly("operator", "viewer");
        assertThat(
                        jdbc.queryForList(
                                "SELECT DISTINCT rs.scope FROM role_scopes rs "
                                        + "JOIN user_roles ur ON rs.role_id = ur.role_id "
                                        + "WHERE ur.user_id = 'existing-user' ORDER BY rs.scope",
                                String.class))
                .containsExactly("payments:read", "payments:write");
        assertThat(
                        jdbc.queryForList(
                                "SELECT role_name FROM roles ORDER BY role_name", String.class))
                .containsExactly("operator", "unassigned", "viewer");
        assertThat(jdbc.queryForList("SELECT role_id FROM roles ORDER BY role_name", Long.class))
                .containsExactlyElementsOf(ids);
        jdbc.update("INSERT INTO roles(role_name) VALUES('new-role')");
        Long newId =
                jdbc.queryForObject(
                        "SELECT role_id FROM roles WHERE role_name = 'new-role'", Long.class);
        assertThat(ids).doesNotContain(newId);
    }

    private DriverManagerDataSource dataSource() {
        return new DriverManagerDataSource(
                "jdbc:h2:mem:roles-" + UUID.randomUUID() + ";DB_CLOSE_DELAY=-1", "sa", "");
    }
}
