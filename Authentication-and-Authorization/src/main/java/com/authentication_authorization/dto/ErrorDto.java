package com.authentication_authorization.dto;

import org.springframework.http.HttpStatus;

public record ErrorDto(String message, HttpStatus status) {
}