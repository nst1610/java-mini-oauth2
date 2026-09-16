package ru.yandex.practicum.oauth0.rs.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import ru.yandex.practicum.oauth0.common.ApiErrors;
import ru.yandex.practicum.oauth0.common.ApiException;
import ru.yandex.practicum.oauth0.common.RequestLog;
import ru.yandex.practicum.oauth0.common.TokenCoder;
import ru.yandex.practicum.oauth0.common.dto.TokenClaims;
import ru.yandex.practicum.oauth0.rs.config.ResourceProperties;

@Component
@RequiredArgsConstructor
public class BearerFilter extends OncePerRequestFilter {
    private final TokenCoder codec;
    private final ResourceProperties properties;
    private final IntrospectionClient client;
    private final ObjectMapper json;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {
        try {
            var headers = Collections.list(request.getHeaders("Authorization"));
            if (headers.size() != 1 || !headers.get(0).matches("(?i)Bearer [A-Za-z0-9_.-]+")) {
                throw new ApiException(401, "invalid_token", "Expected Authorization: Bearer <access_token>");
            }
            String token = headers.get(0).substring(7);
            TokenClaims claims = codec.verify(token, "AT", properties.getAudience());
            if (!client.active(token)) {
                throw ApiException.invalidToken();
            }
            String scope = switch (request.getMethod()) {
                case "GET" -> "payments:read";
                case "POST" -> "payments:write";
                default -> null;
            };
            if (scope != null && !claims.getScopes().contains(scope)) {
                throw new ApiException(403, "insufficient_scope", "Required scope: " + scope);
            }
            request.setAttribute("principal", claims);
        } catch (ApiException e) {
            RequestLog.failure(request, e);
            response.setStatus(e.getStatus());
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            if (e.getStatus() == 401 || e.getStatus() == 403) {
                response.setHeader("WWW-Authenticate", "Bearer error=\"" + e.getError() + "\"");
            }
            json.writeValue(response.getOutputStream(), ApiErrors.body(e));
            return;
        }
        chain.doFilter(request, response);
    }
}
