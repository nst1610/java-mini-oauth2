package ru.yandex.practicum.oauth0.common;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotAcceptableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@RestControllerAdvice
public class ApiErrors {
    public static Map<String, String> body(ApiException e) {
        return Map.of("error", e.getError(), "error_description", e.getMessage());
    }

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<?> api(ApiException e, HttpServletRequest request) {
        RequestLog.failure(request, e);
        return response(e);
    }

    private ResponseEntity<?> response(ApiException e) {
        return ResponseEntity.status(e.getStatus()).body(body(e));
    }

    @ExceptionHandler({
        MethodArgumentNotValidException.class,
        HttpMessageNotReadableException.class
    })
    public ResponseEntity<?> invalid(Exception e, HttpServletRequest request) {
        return api(new ApiException(400, "invalid_request", "Invalid JSON or missing/invalid parameters"), request);
    }

    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<?> missing(HttpServletRequest request) {
        return api(new ApiException(404, "not_found", "Endpoint not found"), request);
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<?> method(HttpServletRequest request) {
        return api(new ApiException(405, "method_not_allowed", "Method not allowed"), request);
    }

    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<?> contentType(HttpServletRequest request) {
        return api(new ApiException(415, "unsupported_media_type", "Expected Content-Type: application/json"), request);
    }

    @ExceptionHandler(HttpMediaTypeNotAcceptableException.class)
    public ResponseEntity<?> accept(HttpServletRequest request) {
        RequestLog.failure(request, new ApiException(406, "not_acceptable", "Response requires application/json"));
        return ResponseEntity.status(406).build();
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> unexpected(Exception e, HttpServletRequest request) {
        RequestLog.unexpected(request, e);
        return response(new ApiException(500, "server_error", "Internal server error"));
    }
}
