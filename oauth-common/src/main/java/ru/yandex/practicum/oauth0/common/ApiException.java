package ru.yandex.practicum.oauth0.common;

public class ApiException extends RuntimeException {
    private final int status;
    private final String error;

    public ApiException(int status, String error, String description) {
        super(description);
        this.status = status;
        this.error = error;
    }

    public int getStatus() {
        return status;
    }

    public String getError() {
        return error;
    }

    public static ApiException invalidToken() {
        return new ApiException(401, "invalid_token", "Token is invalid, expired or not yet valid");
    }
}
