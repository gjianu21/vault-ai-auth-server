package com.vaultai.auth.config;

import java.time.Instant;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.vaultai.auth.model.AppUser;
import com.vaultai.auth.model.Role;
import com.vaultai.auth.repository.AppUserRepository;
import com.vaultai.auth.util.EmailNormalizer;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/** Creates a verified test user on the "local" and "demo" profiles only. */
@Slf4j
@Component
@Profile({"local", "demo"})
@RequiredArgsConstructor
public class LocalTestUserSeeder implements ApplicationRunner {

    private final AppUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AppProperties properties;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        AppProperties.TestUser testUser = properties.testUser();
        if (testUser == null || !StringUtils.hasText(testUser.email())) {
            return;
        }

        String email = EmailNormalizer.normalize(testUser.email());
        if (userRepository.existsByEmail(email)) {
            return;
        }

        userRepository.save(AppUser.builder()
                .email(email)
                .passwordHash(passwordEncoder.encode(testUser.password()))
                .role(Role.RELATIONSHIP_MANAGER)
                .enabled(true)
                .createdAt(Instant.now())
                .build());
        log.info("Local test user created: {}", email);
    }
}