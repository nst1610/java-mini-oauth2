package ru.yandex.practicum.oauth0.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.model.Revocation;
import ru.yandex.practicum.oauth0.auth.model.RevocationId;

public interface RevocationRepository extends JpaRepository<Revocation, RevocationId> {}
