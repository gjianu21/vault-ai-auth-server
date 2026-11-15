package com.vaultai.auth.security;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Stream;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;

import com.vaultai.auth.model.OAuth2AuthorizationEntity;
import com.vaultai.auth.repository.OAuth2AuthorizationRepository;
import com.vaultai.auth.util.JavaSerialization;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Stores OAuth2 authorizations in Oracle through JPA.
 * Replaces JdbcOAuth2AuthorizationService, whose token searches on BLOB columns do not work on Oracle.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    /** Lifetime of an authorization that has no token yet (the login is still in progress). */
    private static final Duration PENDING_AUTHORIZATION_TTL = Duration.ofMinutes(10);

    private final OAuth2AuthorizationRepository repository;

    @Override
    @Transactional
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        repository.save(toEntity(authorization));
    }

    @Override
    @Transactional
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        repository.deleteById(authorization.getId());
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return repository.findById(id).map(this::toAuthorization).orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");

        Optional<OAuth2AuthorizationEntity> result;
        if (tokenType == null) {
            result = repository.findByAnyTokenValue(token);
        } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
            result = repository.findByStateValue(token);
        } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
            result = repository.findByAuthorizationCodeValue(token);
        } else if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            result = repository.findByAccessTokenValue(token);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            result = repository.findByRefreshTokenValue(token);
        } else if (OidcParameterNames.ID_TOKEN.equals(tokenType.getValue())) {
            result = repository.findByOidcIdTokenValue(token);
        } else {
            result = Optional.empty();
        }
        return result.map(this::toAuthorization).orElse(null);
    }

    /** Deletes every authorization (codes, access and refresh tokens) of one user. */
    @Transactional
    public int removeAllForPrincipal(String principalName) {
        return repository.deleteByPrincipalName(principalName);
    }

    @Scheduled(cron = "0 */30 * * * *")
    @Transactional
    public void removeExpired() {
        int removed = repository.deleteExpired(Instant.now());
        if (removed > 0) {
            log.debug("Removed {} expired OAuth2 authorizations", removed);
        }
    }

    private OAuth2AuthorizationEntity toEntity(OAuth2Authorization authorization) {
        OAuth2AuthorizationEntity entity = new OAuth2AuthorizationEntity();
        entity.setId(authorization.getId());
        entity.setRegisteredClientId(authorization.getRegisteredClientId());
        entity.setPrincipalName(authorization.getPrincipalName());
        entity.setStateValue(authorization.getAttribute(OAuth2ParameterNames.STATE));
        entity.setAuthorizationCodeValue(tokenValue(authorization.getToken(OAuth2AuthorizationCode.class)));
        entity.setAccessTokenValue(tokenValue(authorization.getAccessToken()));
        entity.setRefreshTokenValue(tokenValue(authorization.getRefreshToken()));
        entity.setOidcIdTokenValue(tokenValue(authorization.getToken(OidcIdToken.class)));
        entity.setExpiresAt(latestExpiry(authorization));
        entity.setAuthorizationData(JavaSerialization.serialize(authorization));
        return entity;
    }

    private OAuth2Authorization toAuthorization(OAuth2AuthorizationEntity entity) {
        return JavaSerialization.deserialize(entity.getAuthorizationData(), OAuth2Authorization.class);
    }

    private static String tokenValue(OAuth2Authorization.Token<? extends OAuth2Token> token) {
        return token == null ? null : token.getToken().getTokenValue();
    }

    private static Instant latestExpiry(OAuth2Authorization authorization) {
        return Stream.<OAuth2Authorization.Token<? extends OAuth2Token>>of(
                        authorization.getToken(OAuth2AuthorizationCode.class),
                        authorization.getAccessToken(),
                        authorization.getRefreshToken(),
                        authorization.getToken(OidcIdToken.class))
                .filter(Objects::nonNull)
                .map(token -> token.getToken().getExpiresAt())
                .filter(Objects::nonNull)
                .max(Comparator.naturalOrder())
                .orElse(Instant.now().plus(PENDING_AUTHORIZATION_TTL));
    }
}