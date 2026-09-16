package ru.yandex.practicum.oauth0.common;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public final class RequestLog {
    private static final Set<String> PATHS =
            Set.of(
                    "/token",
                    "/token/refresh",
                    "/revoke",
                    "/introspect",
                    "/api/payments");
    private static final Set<String> METHODS =
            Set.of("GET", "POST", "PUT", "DELETE");

    private RequestLog() {}

    public static void failure(HttpServletRequest request, ApiException error) {
        log.warn(
                "Request rejected: method={}, path={}, status={}, error={}",
                method(request),
                path(request),
                error.getStatus(),
                error.getError());
    }

    public static void unexpected(HttpServletRequest request, Exception error) {
        log.error(
                "Request failed: method={}, path={}, status=500, error=server_error, type={},"
                        + " stack={}",
                method(request),
                path(request),
                error.getClass().getName(),
                error.getStackTrace());
    }

    private static String method(HttpServletRequest request) {
        String method = request.getMethod();
        return method != null && METHODS.contains(method) ? method : "OTHER";
    }

    private static String path(HttpServletRequest request) {
        String path = request.getServletPath();
        if (path == null || path.isEmpty()) {
            path = request.getRequestURI();
        }
        return path != null && PATHS.contains(path) ? path : "<unmapped>";
    }
}
