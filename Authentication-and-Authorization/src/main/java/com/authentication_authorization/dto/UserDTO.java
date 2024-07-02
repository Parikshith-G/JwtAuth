package com.authentication_authorization.dto;

public record UserDTO(
        String userName,
        String password,
        String email,
        String role
) {
}
