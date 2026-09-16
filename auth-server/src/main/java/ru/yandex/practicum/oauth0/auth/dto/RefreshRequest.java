package ru.yandex.practicum.oauth0.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@AllArgsConstructor
@Setter
@NoArgsConstructor
public class RefreshRequest {
    @JsonProperty("client_id")
    @NotBlank
    private String clientId;

    @JsonProperty("client_secret")
    @NotBlank
    private String clientSecret;

    @JsonProperty("refresh_token")
    @NotBlank
    private String refreshToken;

    @JsonProperty("grant_type")
    private String grantType;
}
