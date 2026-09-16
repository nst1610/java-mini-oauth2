package ru.yandex.practicum.oauth0.rs;

import java.time.Clock;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import ru.yandex.practicum.oauth0.common.ApiErrors;
import ru.yandex.practicum.oauth0.common.TokenCoder;
import ru.yandex.practicum.oauth0.rs.config.ResourceProperties;

@SpringBootApplication
@EnableConfigurationProperties(ResourceProperties.class)
@Import(ApiErrors.class)
public class ResourceApp {
    public static void main(String[] args) {
        SpringApplication.run(ResourceApp.class, args);
    }

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    TokenCoder tokenCodec(ResourceProperties p, Clock clock) {
        return new TokenCoder(p.getSecret(), p.getIssuer(), p.getSkew(), clock);
    }
}
