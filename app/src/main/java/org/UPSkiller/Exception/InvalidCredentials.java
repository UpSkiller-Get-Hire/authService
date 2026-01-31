package org.UPSkiller.Exception;

public class InvalidCredentials extends RuntimeException {
    public InvalidCredentials() {
        super("Invalid credentials");
    }
}
