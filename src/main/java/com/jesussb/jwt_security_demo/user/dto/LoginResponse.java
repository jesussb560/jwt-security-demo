package com.jesussb.jwt_security_demo.user.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginResponse(
        @NotBlank
        String token
) {
}
