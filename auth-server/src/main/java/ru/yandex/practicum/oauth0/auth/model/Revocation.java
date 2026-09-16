package ru.yandex.practicum.oauth0.auth.model;

import jakarta.persistence.Column;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "revocation")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Revocation {
    @EmbeddedId
    private RevocationId id;

    @Column(name = "exp", nullable = false)
    private long exp;
}
