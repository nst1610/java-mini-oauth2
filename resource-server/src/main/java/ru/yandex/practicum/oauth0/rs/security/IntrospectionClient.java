package ru.yandex.practicum.oauth0.rs.security;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import ru.yandex.practicum.oauth0.common.ApiException;
import ru.yandex.practicum.oauth0.rs.config.ResourceProperties;

@Component
public class IntrospectionClient {
    private final RestClient client;

    public IntrospectionClient(ResourceProperties properties) {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(2000);
        factory.setReadTimeout(2000);
        client = RestClient.builder()
            .baseUrl(properties.getAuthUrl())
            .requestFactory(factory)
            .build();
    }

    public boolean active(String token) {
        try {
            JsonNode response = client.post()
                .uri("/introspect")
                .body(Map.of("token", token))
                .retrieve()
                .body(JsonNode.class);
            if (response == null || !response.path("active").isBoolean()) {
                throw new ApiException(503, "auth_unavailable", "Invalid response from authorization server");
            }
            return response.path("active").booleanValue();
        } catch (RestClientException e) {
            throw new ApiException(503, "auth_unavailable", "Authorization server is unavailable");
        }
    }
}
