package ru.yandex.practicum.oauth0.auth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import ru.yandex.practicum.oauth0.auth.model.RefreshEntry;

public interface RefreshEntryRepository extends JpaRepository<RefreshEntry, String> {
}
