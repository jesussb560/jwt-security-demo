package com.jesussb.jwt_security_demo.common.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record LoginResponse(
        @NotBlank
        String token
) {
}
