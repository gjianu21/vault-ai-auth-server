package com.vaultai.auth.security;

import java.io.Serial;
import java.util.Collection;
import java.util.UUID;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import lombok.Getter;

/**
 * The logged-in user. Same as Spring's User (username = email), plus the user id,
 * which goes into the "sub" claim of the tokens.
 */
@Getter
public class AppUserPrincipal extends User {

    @Serial
    private static final long serialVersionUID = 1L;

    private final UUID userId;

    public AppUserPrincipal(UUID userId, String email, String passwordHash, boolean enabled,
                            boolean accountNonLocked, Collection<? extends GrantedAuthority> authorities) {
        super(email, passwordHash, enabled, true, true, accountNonLocked, authorities);
        this.userId = userId;
    }
}