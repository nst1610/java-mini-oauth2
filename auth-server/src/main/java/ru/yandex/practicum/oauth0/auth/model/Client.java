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
@Table(name = "clients")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Client {
    @Id
    @Column(name = "client_id", nullable = false, length = 100)
    private String id;

    @Column(name = "client_secret_hash", nullable = false, length = 100)
    private String secretHash;

    @Column(name = "aud", nullable = false, length = 200)
    private String audience;

    @Column(name = "info", nullable = false, length = 4000)
    private String info;

    @ElementCollection
    @CollectionTable(name = "client_grants", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "grant_type", nullable = false, length = 100)
    private Set<String> grants = new LinkedHashSet<>();

    @ElementCollection
    @CollectionTable(name = "client_scopes", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope", nullable = false, length = 200)
    private Set<String> scopes = new LinkedHashSet<>();

    public Client(String id, String secretHash, String audience, String info) {
        this.id = id;
        this.secretHash = secretHash;
        this.audience = audience;
        this.info = info;
    }
}
