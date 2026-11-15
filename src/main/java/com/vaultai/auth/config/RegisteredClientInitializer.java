package com.vaultai.auth.config;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Creates (or updates) the vault-ai-be OAuth2 client in Oracle at startup,
 * so its settings always match application.yml.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RegisteredClientInitializer implements ApplicationRunner {

    private static final String REDIRECT_PATH = "/login/oauth2/code/vault-ai";

    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;
    private final AppProperties properties;

    @Override
    public void run(ApplicationArguments args) {
        AppProperties.OAuth2 oauth2 = properties.oauth2();

        RegisteredClient client = RegisteredClient.withId(oauth2.clientId())
                .clientId(oauth2.clientId())
                .clientName("Vault AI backend")
                .clientSecret(passwordEncoder.encode(oauth2.clientSecret()))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // through the Vite proxy (dev) and directly to the backend
                .redirectUri(properties.frontendUrl() + REDIRECT_PATH)
                .redirectUri(properties.backendUrl() + REDIRECT_PATH)
                .postLogoutRedirectUri(properties.frontendUrl())
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(oauth2.accessTokenTtl())
                        .refreshTokenTimeToLive(oauth2.refreshTokenTtl())
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        // save() inserts the client the first time and updates it afterwards (same id)
        registeredClientRepository.save(client);
        log.info("OAuth2 client '{}' is registered", oauth2.clientId());
    }
}