package com.vaultai.auth.config;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.jwk.RSAKey;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Provides the RSA key used to sign JWTs.
 * Production: loaded from a PKCS12 keystore, so tokens stay valid across restarts.
 * Local profile: a temporary key is generated if no keystore is configured.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RsaKeyProvider {

    private final AppProperties properties;
    private final ResourceLoader resourceLoader;

    public RSAKey loadRsaKey() {
        AppProperties.Jwk jwk = properties.jwk();

        if (StringUtils.hasText(jwk.keystorePath())) {
            return loadFromKeystore(jwk);
        }
        if (jwk.generateIfMissing()) {
            log.warn("No JWT keystore configured: generating a temporary RSA key. "
                    + "Tokens become invalid on restart. Use this only for local development.");
            return generateKey();
        }
        throw new IllegalStateException(
                "No JWT signing key configured. Set app.jwk.keystore-path "
                        + "or enable app.jwk.generate-if-missing (local profile only).");
    }

    private RSAKey loadFromKeystore(AppProperties.Jwk jwk) {
        char[] password = jwk.keystorePassword() == null ? new char[0] : jwk.keystorePassword().toCharArray();

        try (InputStream input = resourceLoader.getResource(jwk.keystorePath()).getInputStream()) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(input, password);

            RSAPrivateKey privateKey = (RSAPrivateKey) keyStore.getKey(jwk.keyAlias(), password);
            Certificate certificate = keyStore.getCertificate(jwk.keyAlias());
            if (privateKey == null || certificate == null) {
                throw new IllegalStateException("Alias '" + jwk.keyAlias() + "' not found in the JWT keystore");
            }

            RSAPublicKey publicKey = (RSAPublicKey) certificate.getPublicKey();
            log.info("JWT signing key loaded from keystore (alias: {})", jwk.keyAlias());
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(jwk.keyAlias())
                    .build();
        } catch (IOException | GeneralSecurityException ex) {
            throw new IllegalStateException("Could not load the JWT signing key from the keystore", ex);
        }
    }

    private RSAKey generateKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate())
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException("Could not generate an RSA key", ex);
        }
    }
}