package ru.yandex.practicum.oauth0.auth.repository;

import jakarta.persistence.EntityManager;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.hibernate.dialect.PostgreSQLDialect;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import ru.yandex.practicum.oauth0.auth.model.Client;
import ru.yandex.practicum.oauth0.auth.model.RefreshEntry;
import ru.yandex.practicum.oauth0.auth.model.RevocationId;
import ru.yandex.practicum.oauth0.auth.model.Role;
import ru.yandex.practicum.oauth0.auth.model.User;

@Repository
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthRepository {
    private final UserRepository userRepository;
    private final ClientRepository clientRepository;
    private final RefreshEntryRepository refreshEntryRepository;
    private final RevocationRepository revocationRepository;
    private final EntityManager entityManager;

    public User getUserByName(String name) {
        return userRepository.findByUsername(name).orElse(null);
    }

    public User getUser(String id) {
        return userRepository.findById(id).orElse(null);
    }

    public Client getClient(String id) {
        return clientRepository.findById(id).orElse(null);
    }

    public List<String> getGrants(String id) {
        return clientRepository.findById(id)
                .map(client -> client.getGrants().stream().sorted().toList())
                .orElseGet(List::of);
    }

    public List<String> getClientScopes(String id) {
        return clientRepository.findById(id)
                .map(client -> client.getScopes().stream().sorted().toList())
                .orElseGet(List::of);
    }

    public List<String> getRoles(String userId) {
        return userRepository.findById(userId)
                .map(user -> user.getRoles().stream().map(Role::getName).sorted().toList())
                .orElseGet(List::of);
    }

    public List<String> getUserScopes(String userId) {
        return userRepository.findById(userId)
                .map(user -> user.getRoles().stream()
                    .flatMap(role -> role.getScopes().stream())
                    .distinct()
                    .sorted()
                    .toList())
            .orElseGet(List::of);
    }

    @Transactional
    public void saveRefresh(RefreshEntry entry, List<String> scopes) {
        entry.getScopes().addAll(scopes);
        refreshEntryRepository.save(entry);
    }

    public RefreshEntry getRefresh(String id) {
        return refreshEntryRepository.findById(id).orElse(null);
    }

    public List<String> getRefreshScopes(String id) {
        return refreshEntryRepository
                .findById(id)
                .map(entry -> entry.getScopes().stream().sorted().toList())
                .orElseGet(List::of);
    }

    @Transactional
    public void markRotated(String id) {
        RefreshEntry entry = refreshEntryRepository.findById(id).orElseThrow();
        entry.rotate();
    }

    public boolean revoked(String type, String id) {
        return revocationRepository.existsById(new RevocationId(type, id));
    }

    @Transactional
    public void revoke(String type, String id, long exp) {
        var dialect = entityManager.getEntityManagerFactory()
            .unwrap(SessionFactoryImplementor.class)
            .getJdbcServices()
            .getDialect();
        String sql;
        if (dialect instanceof PostgreSQLDialect) {
            sql =
                    """
                    INSERT INTO revocation(token_type, token_id, exp)
                    VALUES(:type, :id, :exp) ON CONFLICT DO NOTHING
                    """;
        } else {
            sql =
                    """
                    MERGE INTO revocation(token_type, token_id, exp)
                    KEY(token_type, token_id) VALUES(:type, :id, :exp)
                    """;
        }
        entityManager
            .createNativeQuery(sql)
            .setParameter("type", type)
            .setParameter("id", id)
            .setParameter("exp", exp)
            .executeUpdate();
    }
}
