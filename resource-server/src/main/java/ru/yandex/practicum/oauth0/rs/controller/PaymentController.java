package ru.yandex.practicum.oauth0.rs.controller;

import jakarta.validation.Valid;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestAttribute;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ru.yandex.practicum.oauth0.common.dto.TokenClaims;
import ru.yandex.practicum.oauth0.rs.dto.PaymentRequest;
import ru.yandex.practicum.oauth0.rs.service.PaymentService;

@RestController
@RequestMapping("/api/payments")
@RequiredArgsConstructor
public class PaymentController {
    private final PaymentService service;

    @GetMapping
    public List<Map<String, Object>> list() {
        return service.list();
    }

    @PostMapping
    public Map<String, Object> create(@Valid @RequestBody PaymentRequest request,
                                      @RequestAttribute("principal") TokenClaims principal) {
        return service.create(request, principal.getSub());
    }
}
