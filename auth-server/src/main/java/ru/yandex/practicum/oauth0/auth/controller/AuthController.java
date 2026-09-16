package ru.yandex.practicum.oauth0.auth.controller;

import jakarta.validation.Valid;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import ru.yandex.practicum.oauth0.auth.dto.RefreshRequest;
import ru.yandex.practicum.oauth0.auth.dto.TokenInput;
import ru.yandex.practicum.oauth0.auth.dto.TokenRequest;
import ru.yandex.practicum.oauth0.auth.dto.TokenResponse;
import ru.yandex.practicum.oauth0.auth.service.AuthService;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthService service;

    @PostMapping("/token")
    public TokenResponse token(@Valid @RequestBody TokenRequest request) {
        return service.token(request);
    }

    @PostMapping("/token/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return service.refresh(request);
    }

    @PostMapping("/introspect")
    public Map<String, Object> introspect(@Valid @RequestBody TokenInput request) {
        return service.introspect(request.getToken());
    }

    @PostMapping("/revoke")
    public ResponseEntity<Void> revoke(@Valid @RequestBody TokenInput request) {
        service.revoke(request.getToken(), request.getTokenTypeHint());
        return ResponseEntity.ok().build();
    }
}
