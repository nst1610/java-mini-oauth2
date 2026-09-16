package ru.yandex.practicum.oauth0.rs.config;

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
@ConfigurationProperties("rs")
@Getter
@AllArgsConstructor
@Setter
@NoArgsConstructor
public class ResourceProperties {

    @NotBlank
    private String issuer;

    @NotBlank
    private String audience;

    @NotBlank
    private String secret;

    @Min(0)
    @Max(300)
    private long skew;

    @NotBlank
    private String authUrl;
}
