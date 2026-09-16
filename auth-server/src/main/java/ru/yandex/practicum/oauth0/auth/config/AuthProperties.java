package ru.yandex.practicum.oauth0.auth.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("auth")
@Getter
@AllArgsConstructor
@Setter
@NoArgsConstructor
public class AuthProperties {

    @NotBlank
    private String issuer;

    @NotBlank
    private String audience;

    @NotBlank
    private String secret;

    @Min(1)
    @Max(86400)
    private long accessTtlSec;

    @Min(1)
    @Max(365)
    private long refreshTtlDays;

    @Min(0)
    @Max(300)
    private long skew;
}
