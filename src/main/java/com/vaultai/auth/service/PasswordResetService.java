package com.vaultai.auth.service;

import java.time.Instant;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.vaultai.auth.config.AppProperties;
import com.vaultai.auth.exception.InvalidTokenException;
import com.vaultai.auth.exception.TokenExpiredException;
import com.vaultai.auth.model.AppUser;
import com.vaultai.auth.model.PasswordResetToken;
import com.vaultai.auth.repository.AppUserRepository;
import com.vaultai.auth.repository.PasswordResetTokenRepository;
import com.vaultai.auth.security.LoginAttemptService;
import com.vaultai.auth.service.EmailEvents.PasswordChangedEmailRequested;
import com.vaultai.auth.service.EmailEvents.PasswordResetEmailRequested;
import com.vaultai.auth.util.EmailNormalizer;
import com.vaultai.auth.util.SecureTokens;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class PasswordResetService {

    private final AppUserRepository userRepository;
    private final PasswordResetTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final LoginAttemptService loginAttemptService;
    private final ApplicationEventPublisher eventPublisher;
    private final AppProperties properties;

    /** Sends a reset link only if a verified account exists, but always responds the same way. */
    @Transactional
    public void requestReset(String rawEmail) {
        String email = EmailNormalizer.normalize(rawEmail);

        userRepository.findByEmail(email)
                .filter(AppUser::isEnabled)
                .ifPresent(this::issueResetToken);
    }

    /** Checks the link before the "new password" page is shown. */
    @Transactional(readOnly = true)
    public void validateToken(String rawToken) {
        PasswordResetToken token = findToken(rawToken);
        if (token.isExpired(Instant.now())) {
            throw new TokenExpiredException();
        }
    }

    @Transactional(noRollbackFor = TokenExpiredException.class)
    public void resetPassword(String rawToken, String newPassword) {
        PasswordResetToken token = findToken(rawToken);

        if (token.isExpired(Instant.now())) {
            tokenRepository.delete(token);
            throw new TokenExpiredException();
        }

        AppUser user = token.getUser();
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        tokenRepository.delete(token);
        loginAttemptService.loginSucceeded(user.getEmail()); // unlocks the account

        eventPublisher.publishEvent(new CredentialsChangedEvent(user.getId(), user.getEmail()));
        eventPublisher.publishEvent(new PasswordChangedEmailRequested(user.getEmail()));
        log.info("Password reset for user {}", user.getId());
    }

    private void issueResetToken(AppUser user) {
        tokenRepository.deleteByUser(user);

        String rawToken = SecureTokens.newToken();
        Instant now = Instant.now();
        tokenRepository.save(PasswordResetToken.builder()
                .tokenHash(SecureTokens.sha256(rawToken))
                .user(user)
                .createdAt(now)
                .expiresAt(now.plus(properties.passwordReset().expiry()))
                .build());

        String link = UriComponentsBuilder.fromUriString(properties.publicUrl())
                .path("/reset-password")
                .queryParam("token", rawToken)
                .toUriString();
        eventPublisher.publishEvent(new PasswordResetEmailRequested(user.getEmail(), link));
    }

    private PasswordResetToken findToken(String rawToken) {
        if (!StringUtils.hasText(rawToken)) {
            throw new InvalidTokenException();
        }
        return tokenRepository.findByTokenHash(SecureTokens.sha256(rawToken))
                .orElseThrow(InvalidTokenException::new);
    }
}