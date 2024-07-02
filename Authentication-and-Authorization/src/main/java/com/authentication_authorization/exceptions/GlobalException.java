package com.authentication_authorization.exceptions;

import com.authentication_authorization.dto.ErrorDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalException {

    @ExceptionHandler(AppException.class)
    public ResponseEntity<ErrorDto> allExceptions(AppException exception) {
        ErrorDto dto = new ErrorDto(exception.getMessage(), exception.getStatus());
        return new ResponseEntity<ErrorDto>(dto, exception.getStatus());

    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDto> actualError(Exception exception) {
        ErrorDto dto = new ErrorDto(exception.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        return new ResponseEntity<ErrorDto>(dto, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}