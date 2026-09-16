package ru.yandex.practicum.oauth0.auth.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import java.util.List;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@AllArgsConstructor
@Setter
@NoArgsConstructor
public class TokenRequest {
    @JsonProperty("grant_type")
    @NotBlank
    private String grantType;

    @JsonProperty("client_id")
    @NotBlank
    private String clientId;

    @JsonProperty("client_secret")
    @NotBlank
    private String clientSecret;

    private String username;

    private String password;

    private List<@NotBlank String> scopes;
}
