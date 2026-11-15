package com.vaultai.auth.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.vaultai.auth.model.AppUser;
import com.vaultai.auth.model.PasswordResetToken;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, UUID> {

    Optional<PasswordResetToken> findByTokenHash(String tokenHash);

    /** Runs immediately, so a new token can be inserted in the same transaction. */
    @Modifying(flushAutomatically = true)
    @Query("delete from PasswordResetToken t where t.user = :user")
    int deleteByUser(@Param("user") AppUser user);
}