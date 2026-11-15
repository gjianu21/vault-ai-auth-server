package com.vaultai.auth.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.vaultai.auth.model.AppUser;
import com.vaultai.auth.model.EmailVerificationToken;

public interface EmailVerificationTokenRepository extends JpaRepository<EmailVerificationToken, UUID> {

    Optional<EmailVerificationToken> findByTokenHash(String tokenHash);

    Optional<EmailVerificationToken> findByUser(AppUser user);

    /** Runs immediately, so a new token can be inserted in the same transaction. */
    @Modifying(flushAutomatically = true)
    @Query("delete from EmailVerificationToken t where t.user = :user")
    int deleteByUser(@Param("user") AppUser user);
}