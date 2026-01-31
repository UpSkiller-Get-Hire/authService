package org.UPSkiller.Exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<?> handleEmailAlreadyExistsException(EmailAlreadyExistsException ex) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(Map.of(
                        "timestamp", Instant.now(),
                        "error", "EMAIL_ALREADY_EXISTS",
                        "message", ex.getMessage()
                )
        );
    }

    @ExceptionHandler(InvalidCredentials.class)
    public ResponseEntity<?> handleInvalidCredentials(InvalidCredentials ex) {
        return ResponseEntity
                .status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                        "timestamp", Instant.now(),
                        "error", "Invalid Credentials",
                        "message", ex.getMessage()
                ));
    }

}
