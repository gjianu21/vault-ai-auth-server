package com.vaultai.auth.service;

import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;

import com.vaultai.auth.service.EmailEvents.AccountExistsEmailRequested;
import com.vaultai.auth.service.EmailEvents.PasswordChangedEmailRequested;
import com.vaultai.auth.service.EmailEvents.PasswordResetEmailRequested;
import com.vaultai.auth.service.EmailEvents.VerificationEmailRequested;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Sends emails only after the transaction is committed, so no email goes out
 * for data that was rolled back. An email failure never breaks the user's request.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class EmailEventListener {

    private final EmailSender emailSender;

    @TransactionalEventListener(fallbackExecution = true)
    public void on(VerificationEmailRequested event) {
        safely(() -> emailSender.sendVerificationEmail(event.email(), event.verificationLink()));
    }

    @TransactionalEventListener(fallbackExecution = true)
    public void on(AccountExistsEmailRequested event) {
        safely(() -> emailSender.sendAccountExistsEmail(
                event.email(), event.loginLink(), event.forgotPasswordLink()));
    }

    @TransactionalEventListener(fallbackExecution = true)
    public void on(PasswordResetEmailRequested event) {
        safely(() -> emailSender.sendPasswordResetEmail(event.email(), event.resetLink()));
    }

    @TransactionalEventListener(fallbackExecution = true)
    public void on(PasswordChangedEmailRequested event) {
        safely(() -> emailSender.sendPasswordChangedEmail(event.email()));
    }

    private void safely(Runnable action) {
        try {
            action.run();
        } catch (RuntimeException ex) {
            log.error("Could not send email: {}", ex.getMessage(), ex);
        }
    }
}