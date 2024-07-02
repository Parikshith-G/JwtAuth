package com.authentication_authorization.exceptions;

import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
public class AppException extends RuntimeException {

    private final String message;

    private final HttpStatus status;

    public AppException(String message, HttpStatus status) {
        super(message + " " + status);
        this.message = message;
        this.status = status;
    }
}