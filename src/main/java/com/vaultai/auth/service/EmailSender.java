package com.vaultai.auth.service;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import com.vaultai.auth.config.AppProperties;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailSender {

    private final JavaMailSender mailSender;
    private final AppProperties properties;

    public void sendVerificationEmail(String to, String verificationLink) {
        long hours = properties.emailVerification().expiry().toHours();
        send(to, "Confirm your Vault AI account", """
                Welcome to Vault AI!

                Please confirm your email address by opening the link below:
                %s

                The link expires in %d hours.
                If you did not create an account, you can ignore this email.
                """.formatted(verificationLink, hours));
    }

    public void sendAccountExistsEmail(String to, String loginLink, String forgotPasswordLink) {
        send(to, "You already have a Vault AI account", """
                Someone tried to create a Vault AI account with this email address,
                but an account already exists.

                Sign in: %s
                Forgot your password? Reset it here: %s

                If this was not you, you can ignore this email. Your account is safe.
                """.formatted(loginLink, forgotPasswordLink));
    }

    public void sendPasswordResetEmail(String to, String resetLink) {
        long minutes = properties.passwordReset().expiry().toMinutes();
        send(to, "Reset your Vault AI password", """
                We received a request to reset your Vault AI password.

                Choose a new password here:
                %s

                The link expires in %d minutes.
                If you did not ask for a reset, you can ignore this email.
                """.formatted(resetLink, minutes));
    }

    public void sendPasswordChangedEmail(String to) {
        send(to, "Your Vault AI password was changed", """
                Your Vault AI password was just changed and you were signed out on all devices.

                If you did not do this, reset your password immediately and contact support.
                """);
    }

    private void send(String to, String subject, String body) {
        if (properties.mailLogOnly()) {
            // local development: no SMTP server, the link is copied from the log
            log.info("[MAIL NOT SENT] to={} subject={}\n{}", to, subject, body);
            return;
        }

        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(properties.mailFrom());
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }
}