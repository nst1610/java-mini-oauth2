package ru.yandex.practicum.oauth0.rs.service;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import ru.yandex.practicum.oauth0.rs.dto.PaymentRequest;

@Service
public class PaymentService {
    public List<Map<String, Object>> list() {
        return List.of(Map.of("id", "p-001", "amount", 100, "currency", "RUB"));
    }

    public Map<String, Object> create(PaymentRequest request, String subject) {
        return Map.of(
                "id", UUID.randomUUID().toString(),
                "amount", request.getAmount(),
                "currency", request.getCurrency(),
                "created_by", subject,
                "status", "simulated");
    }
}
