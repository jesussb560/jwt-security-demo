package com.jesussb.jwt_security_demo.refreshtoken;

import java.time.Duration;

public interface RefreshTokenService {
    String generate(Long userId);
    RefreshToken validate(String token);
    String rotate(String token);
}
