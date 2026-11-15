package com.vaultai.auth.service;

/** Emails to send. They are published inside transactions and sent after commit. */
public final class EmailEvents {

    private EmailEvents() {
    }

    public record VerificationEmailRequested(String email, String verificationLink) {
    }

    public record AccountExistsEmailRequested(String email, String loginLink, String forgotPasswordLink) {
    }

    public record PasswordResetEmailRequested(String email, String resetLink) {
    }

    public record PasswordChangedEmailRequested(String email) {
    }
}