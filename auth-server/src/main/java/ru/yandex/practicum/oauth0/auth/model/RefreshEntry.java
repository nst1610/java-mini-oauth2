package ru.yandex.practicum.oauth0.auth.model;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;
import java.util.LinkedHashSet;
import java.util.Set;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "refresh_index")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RefreshEntry {
    @Id
    @Column(name = "refresh_id", nullable = false, length = 100)
    private String id;

    @Column(name = "user_id", nullable = false, length = 100)
    private String userId;

    @Column(name = "client_id", nullable = false, length = 100)
    private String clientId;

    @Column(name = "exp", nullable = false)
    private long exp;

    @Column(name = "rotated", nullable = false)
    private boolean rotated;

    @ElementCollection
    @CollectionTable(name = "refresh_scopes", joinColumns = @JoinColumn(name = "refresh_id"))
    @Column(name = "scope", nullable = false, length = 200)
    private Set<String> scopes = new LinkedHashSet<>();

    public RefreshEntry(String id, String userId, String clientId, long exp, boolean rotated) {
        this.id = id;
        this.userId = userId;
        this.clientId = clientId;
        this.exp = exp;
        this.rotated = rotated;
    }

    public void rotate() {
        rotated = true;
    }
}
