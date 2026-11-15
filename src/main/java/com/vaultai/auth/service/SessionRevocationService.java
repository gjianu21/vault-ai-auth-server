package com.vaultai.auth.service;

import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.vaultai.auth.security.JpaOAuth2AuthorizationService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * After a password change, signs the user out everywhere:
 * 1. OAuth2 tokens (access, refresh, codes) in the auth-server
 * 2. login sessions in the auth-server
 * 3. sessions in vault-ai-be (internal call)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SessionRevocationService {

    private final JpaOAuth2AuthorizationService authorizationService;
    private final FindByIndexNameSessionRepository<? extends Session> sessionRepository;
    private final RestClient backendRestClient;

    /** Runs only after the password change has been committed. */
    @TransactionalEventListener
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void onCredentialsChanged(CredentialsChangedEvent event) {
        // in the auth-server the principal name is the email
        int authorizations = authorizationService.removeAllForPrincipal(event.email());
        int sessions = revokeAuthServerSessions(event.email());
        revokeBackendSessions(event.userId().toString());

        log.info("Credentials changed for user {}: {} authorizations and {} sessions revoked",
                event.userId(), authorizations, sessions);
    }

    private int revokeAuthServerSessions(String email) {
        Map<String, ? extends Session> sessions = sessionRepository.findByPrincipalName(email);
        sessions.keySet().forEach(sessionRepository::deleteById);
        return sessions.size();
    }

    private void revokeBackendSessions(String userId) {
        try {
            // in vault-ai-be the principal name is the "sub" claim, i.e. the user id
            backendRestClient.post()
                    .uri("/internal/sessions/revoke")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(Map.of("userId", userId))
                    .retrieve()
                    .toBodilessEntity();
        } catch (RestClientException ex) {
            // the password change is kept: backend sessions expire anyway after 15 minutes of inactivity
            log.warn("Could not revoke vault-ai-be sessions: {}", ex.getMessage());
        }
    }
}