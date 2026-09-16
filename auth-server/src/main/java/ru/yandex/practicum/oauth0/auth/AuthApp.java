package ru.yandex.practicum.oauth0.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import ru.yandex.practicum.oauth0.auth.config.AuthProperties;
import ru.yandex.practicum.oauth0.common.ApiErrors;
import ru.yandex.practicum.oauth0.common.TokenCoder;
import java.time.Clock;

@SpringBootApplication
@EnableConfigurationProperties(AuthProperties.class)
@Import(ApiErrors.class)
public class AuthApp {
    public static void main(String[] args) {
        SpringApplication.run(AuthApp.class, args);
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    TokenCoder tokenCodec(AuthProperties p, Clock clock) {
        return new TokenCoder(p.getSecret(), p.getIssuer(), p.getSkew(), clock);
    }
}
