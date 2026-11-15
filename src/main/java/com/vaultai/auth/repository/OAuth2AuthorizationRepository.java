package com.vaultai.auth.repository;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.vaultai.auth.model.OAuth2AuthorizationEntity;

public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {

    Optional<OAuth2AuthorizationEntity> findByStateValue(String state);

    Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(String authorizationCode);

    Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(String accessToken);

    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshToken);

    Optional<OAuth2AuthorizationEntity> findByOidcIdTokenValue(String idToken);

    @Query("""
            select a from OAuth2AuthorizationEntity a
            where a.stateValue = :token
               or a.authorizationCodeValue = :token
               or a.accessTokenValue = :token
               or a.refreshTokenValue = :token
               or a.oidcIdTokenValue = :token
            """)
    Optional<OAuth2AuthorizationEntity> findByAnyTokenValue(@Param("token") String token);

    @Modifying
    @Query("delete from OAuth2AuthorizationEntity a where a.principalName = :principalName")
    int deleteByPrincipalName(@Param("principalName") String principalName);

    @Modifying
    @Query("delete from OAuth2AuthorizationEntity a where a.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);
}