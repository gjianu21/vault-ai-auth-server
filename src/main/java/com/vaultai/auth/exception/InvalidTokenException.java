package com.vaultai.auth.exception;

/** The verification or reset link does not exist (wrong, already used or replaced). */
public class InvalidTokenException extends RuntimeException {

    public InvalidTokenException() {
        super("The link is invalid or has already been used");
    }
}