package com.vaultai.auth.exception;

public class TokenExpiredException extends RuntimeException {

    public TokenExpiredException() {
        super("The link has expired");
    }
}