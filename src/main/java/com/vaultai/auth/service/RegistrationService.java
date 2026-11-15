package com.vaultai.auth.service;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.vaultai.auth.config.AppProperties;
import com.vaultai.auth.exception.InvalidTokenException;
import com.vaultai.auth.exception.TokenExpiredException;
import com.vaultai.auth.model.AppUser;
import com.vaultai.auth.model.EmailVerificationToken;
import com.vaultai.auth.model.Role;
import com.vaultai.auth.repository.AppUserRepository;
import com.vaultai.auth.repository.EmailVerificationTokenRepository;
import com.vaultai.auth.service.EmailEvents.AccountExistsEmailRequested;
import com.vaultai.auth.service.EmailEvents.VerificationEmailRequested;
import com.vaultai.auth.util.EmailNormalizer;
import com.vaultai.auth.util.SecureTokens;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class RegistrationService {

    private final AppUserRepository userRepository;
    private final EmailVerificationTokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final ApplicationEventPublisher eventPublisher;
    private final AppProperties properties;

    // avoids flooding a mailbox with "you already have an account" emails
    private final Cache<String, Boolean> recentAccountExistsNotices = Caffeine.newBuilder()
            .expireAfterWrite(Duration.ofMinutes(5))
            .maximumSize(100_000)
            .build();

    /**
     * Always behaves the same from the outside, so nobody can find out
     * whether an email address already has an account.
     */
    @Transactional
    public void register(String rawEmail, String rawPassword) {
        String email = EmailNormalizer.normalize(rawEmail);
        Optional<AppUser> existing = userRepository.findByEmail(email);

        if (existing.isPresent() && existing.get().isEnabled()) {
            passwordEncoder.encode(rawPassword); // keeps the response time similar to a new account
            notifyAccountAlreadyExists(email);
            return;
        }

        AppUser user;
        if (existing.isPresent()) {
            // account created but not verified yet: send a new link
            user = existing.get();
            Optional<EmailVerificationToken> currentToken = tokenRepository.findByUser(user);
            if (currentToken.isPresent() && wasIssuedRecently(currentToken.get())) {
                log.info("Verification email not resent: a link was issued recently");
                return;
            }
            // the last registration wins (protection against account pre-hijacking)
            user.setPasswordHash(passwordEncoder.encode(rawPassword));
        } else {
            user = AppUser.builder()
                    .email(email)
                    .passwordHash(passwordEncoder.encode(rawPassword))
                    .role(Role.CUSTOMER)
                    .enabled(false)
                    .createdAt(Instant.now())
                    .build();
        }

        userRepository.save(user);
        tokenRepository.deleteByUser(user);
        issueVerificationToken(user);
    }

    @Transactional(noRollbackFor = TokenExpiredException.class)
    public void verifyEmail(String rawToken) {
        if (!StringUtils.hasText(rawToken)) {
            throw new InvalidTokenException();
        }

        EmailVerificationToken token = tokenRepository.findByTokenHash(SecureTokens.sha256(rawToken))
                .orElseThrow(InvalidTokenException::new);

        if (token.isExpired(Instant.now())) {
            tokenRepository.delete(token);
            throw new TokenExpiredException();
        }

        AppUser user = token.getUser();
        user.setEnabled(true);
        tokenRepository.delete(token);
        log.info("Email verified for user {}", user.getId());
    }

    private void issueVerificationToken(AppUser user) {
        String rawToken = SecureTokens.newToken();
        Instant now = Instant.now();

        tokenRepository.save(EmailVerificationToken.builder()
                .tokenHash(SecureTokens.sha256(rawToken))
                .user(user)
                .createdAt(now)
                .expiresAt(now.plus(properties.emailVerification().expiry()))
                .build());

        String link = UriComponentsBuilder.fromUriString(properties.publicUrl())
                .path("/verify-email")
                .queryParam("token", rawToken)
                .toUriString();
        eventPublisher.publishEvent(new VerificationEmailRequested(user.getEmail(), link));
    }

    private boolean wasIssuedRecently(EmailVerificationToken token) {
        return token.getCreatedAt()
                .plus(properties.emailVerification().resendCooldown())
                .isAfter(Instant.now());
    }

    private void notifyAccountAlreadyExists(String email) {
        if (recentAccountExistsNotices.asMap().putIfAbsent(email, Boolean.TRUE) != null) {
            log.info("'Account exists' email not sent: one was sent recently");
            return;
        }
        eventPublisher.publishEvent(new AccountExistsEmailRequested(
                email,
                properties.frontendUrl(),
                properties.publicUrl() + "/forgot-password"));
    }
}