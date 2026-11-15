package com.vaultai.auth.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * All custom settings under the "app" prefix, bound and validated at startup.
 * If a required value is missing, the application fails fast with a clear message.
 */
@Validated
@ConfigurationProperties(prefix = "app")
public record AppProperties(
        @NotBlank String publicUrl,
        @NotBlank String frontendUrl,
        @NotBlank String backendUrl,
        @NotBlank String mailFrom,
        @NotBlank String internalApiKey,
        @Valid @NotNull OAuth2 oauth2,
        @Valid @NotNull Jwk jwk,
        @Valid @NotNull EmailVerification emailVerification,
        @Valid @NotNull PasswordReset passwordReset,
        @Valid @NotNull RateLimit rateLimit,
        @Valid @NotNull LoginLock loginLock,
        TestUser testUser) {

    public record OAuth2(
            @NotBlank String clientId,
            @NotBlank String clientSecret,
            @NotNull Duration accessTokenTtl,
            @NotNull Duration refreshTokenTtl) {
    }

    public record Jwk(
            String keystorePath,
            String keystorePassword,
            String keyAlias,
            boolean generateIfMissing) {
    }

    public record EmailVerification(
            @NotNull Duration expiry,
            @NotNull Duration resendCooldown) {
    }

    public record PasswordReset(@NotNull Duration expiry) {
    }

    public record RateLimit(
            @Min(1) int capacity,
            @NotNull Duration refillPeriod) {
    }

    public record LoginLock(
            @Min(1) int maxAttempts,
            @NotNull Duration lockDuration) {
    }

    /** Only set on the "local" profile. */
    public record TestUser(String email, String password) {
    }
}
