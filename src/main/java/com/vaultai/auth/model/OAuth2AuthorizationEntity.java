package com.vaultai.auth.model;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One OAuth2 authorization (authorization code, access, refresh and ID tokens of one login).
 * The token values are kept in separate VARCHAR2 columns so they can be searched with "=",
 * and the full authorization object is serialized in authorization_data.
 */
@Entity
@Table(name = "oauth2_authorization")
@Getter
@Setter
@NoArgsConstructor
public class OAuth2AuthorizationEntity {

    @Id
    @Column(name = "id", length = 100)
    private String id;

    @Column(name = "registered_client_id", nullable = false, length = 100)
    private String registeredClientId;

    @Column(name = "principal_name", nullable = false, length = 200)
    private String principalName;

    @Column(name = "state_value", length = 500)
    private String stateValue;

    @Column(name = "authorization_code_value", length = 4000)
    private String authorizationCodeValue;

    @Column(name = "access_token_value", length = 4000)
    private String accessTokenValue;

    @Column(name = "refresh_token_value", length = 4000)
    private String refreshTokenValue;

    @Column(name = "oidc_id_token_value", length = 4000)
    private String oidcIdTokenValue;

    /** When the last token of this authorization expires; used to clean up old rows. */
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Lob
    @Column(name = "authorization_data", nullable = false)
    private byte[] authorizationData;
}