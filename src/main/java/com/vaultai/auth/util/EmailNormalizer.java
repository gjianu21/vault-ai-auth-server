package com.vaultai.auth.util;

import java.util.Locale;

public final class EmailNormalizer {

    private EmailNormalizer() {
    }

    /** "  John@Example.COM " -> "john@example.com" */
    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}