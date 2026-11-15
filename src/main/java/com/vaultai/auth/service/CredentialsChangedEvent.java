package com.vaultai.auth.service;

import java.util.UUID;

/** Published when a user's password changes: all of the user's sessions and tokens must be revoked. */
public record CredentialsChangedEvent(UUID userId, String email) {
}