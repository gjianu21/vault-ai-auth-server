package com.vaultai.auth.config;

import java.security.Principal;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.vaultai.auth.security.AppUserPrincipal;

import lombok.RequiredArgsConstructor;

/**
 * OAuth2 / OpenID Connect endpoints: /oauth2/authorize, /oauth2/token, /oauth2/jwks,
 * /userinfo, /connect/logout and /.well-known/openid-configuration.
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final AppProperties properties;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .oauth2AuthorizationServer(authorizationServer -> {
                    http.securityMatcher(authorizationServer.getEndpointsMatcher());
                    authorizationServer.oidc(oidc -> oidc
                            .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(this::mapUserInfo)));
                })
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                // the /userinfo endpoint is called with the access token as a Bearer token
                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()))
                // browsers that are not logged in are sent to the login page
                .exceptionHandling(exceptions -> exceptions.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RsaKeyProvider rsaKeyProvider) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKeyProvider.loadRsaKey()));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // the issuer must match exactly the issuer-uri configured in vault-ai-be
        return AuthorizationServerSettings.builder()
                .issuer(properties.publicUrl())
                .build();
    }

    /**
     * Puts the user id in "sub" (stable even if the email changes),
     * plus the email and the roles, in both the access token and the ID token.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer() {
        return context -> {
            if (!(context.getPrincipal().getPrincipal() instanceof AppUserPrincipal user)) {
                return;
            }

            boolean isAccessToken = OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType());
            boolean isIdToken = OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue());
            if (!isAccessToken && !isIdToken) {
                return;
            }

            context.getClaims()
                    .subject(user.getUserId().toString())
                    .claim("email", user.getUsername())
                    .claim("roles", roles(user));

            if (isIdToken) {
                // only verified accounts can log in
                context.getClaims().claim("email_verified", true);
            }
        };
    }

    /** The /userinfo "sub" must be the same as the ID token "sub". */
    private OidcUserInfo mapUserInfo(OidcUserInfoAuthenticationContext context) {
        OAuth2Authorization authorization = context.getAuthorization();
        Authentication authentication = authorization.getAttribute(Principal.class.getName());

        if (authentication != null && authentication.getPrincipal() instanceof AppUserPrincipal user) {
            return OidcUserInfo.builder()
                    .subject(user.getUserId().toString())
                    .email(user.getUsername())
                    .emailVerified(true)
                    .build();
        }
        return OidcUserInfo.builder().subject(authorization.getPrincipalName()).build();
    }

    private static List<String> roles(AppUserPrincipal user) {
        return user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(authority -> authority.startsWith("ROLE_"))
                .toList();
    }
}