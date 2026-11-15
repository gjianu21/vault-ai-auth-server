package com.vaultai.auth.config;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/**
 * HTTP client for internal calls to vault-ai-be (for example, revoking sessions
 * after a password reset). Every request carries the shared internal API key.
 */
@Configuration
public class BackendClientConfig {

    public static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";

    @Bean
    public RestClient backendRestClient(AppProperties properties) {
        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(3));
        requestFactory.setReadTimeout(Duration.ofSeconds(5));

        return RestClient.builder()
                .baseUrl(properties.backendUrl())
                .requestFactory(requestFactory)
                .defaultHeader(INTERNAL_API_KEY_HEADER, properties.internalApiKey())
                .build();
    }
}