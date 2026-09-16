package ru.yandex.practicum.oauth0.common.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@AllArgsConstructor
@Setter
@NoArgsConstructor
@EqualsAndHashCode
public class TokenClaims {
    private String typ;
    private String alg;
    private String iss;
    private String aud;
    private String sub;

    @JsonProperty("client_id")
    private String clientId;

    private List<String> scopes;
    private List<String> roles;
    private Map<String, Object> info;
    private long iat;
    private long exp;
    private String jti;

    @JsonProperty("refresh_id")
    private String refreshId;
}
