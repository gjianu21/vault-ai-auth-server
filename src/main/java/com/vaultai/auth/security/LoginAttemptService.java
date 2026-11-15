package com.vaultai.auth.security;

import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.stereotype.Service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.vaultai.auth.config.AppProperties;
import com.vaultai.auth.util.EmailNormalizer;

/**
 * Locks an account after too many wrong passwords (default: 5 attempts, 15 minutes).
 * Kept in memory: enough for a single instance.
 */
@Service
public class LoginAttemptService {

    private final int maxAttempts;
    private final Cache<String, AtomicInteger> failedAttempts;

    public LoginAttemptService(AppProperties properties) {
        this.maxAttempts = properties.loginLock().maxAttempts();
        // the counter expires lockDuration after the first failed attempt
        this.failedAttempts = Caffeine.newBuilder()
                .expireAfterWrite(properties.loginLock().lockDuration())
                .maximumSize(100_000)
                .build();
    }

    public void loginFailed(String email) {
        failedAttempts.get(EmailNormalizer.normalize(email), key -> new AtomicInteger()).incrementAndGet();
    }

    public void loginSucceeded(String email) {
        failedAttempts.invalidate(EmailNormalizer.normalize(email));
    }

    public boolean isBlocked(String email) {
        AtomicInteger attempts = failedAttempts.getIfPresent(EmailNormalizer.normalize(email));
        return attempts != null && attempts.get() >= maxAttempts;
    }
}