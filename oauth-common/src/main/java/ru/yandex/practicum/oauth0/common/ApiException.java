package ru.yandex.practicum.oauth0.common;

import lombok.Getter;

@Getter
public class ApiException extends RuntimeException {
    private final int status;
    private final String error;

    public ApiException(int status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    public static ApiException invalidToken() {
        return new ApiException(401, "invalid_token", "Token is invalid, expired or not yet valid");
    }
}
