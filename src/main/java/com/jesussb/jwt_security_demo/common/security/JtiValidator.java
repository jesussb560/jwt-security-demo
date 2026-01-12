package com.jesussb.jwt_security_demo.common.security;

import com.jesussb.jwt_security_demo.common.jwt.JwtStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class JtiValidator implements OAuth2TokenValidator<Jwt> {

    private final JwtStore jwtStore;

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {

        String jti = token.getClaimAsString("jti");

        log.info("jti: {}", jti);

        if (jti == null || jti.isBlank()) {
            log.error("jti is blank");
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Missing jti claim", null)
            );
        }

        if (jwtStore.isRevoked(jti)) {
            log.error("jti is already revoked");
            return OAuth2TokenValidatorResult.failure(
                    new OAuth2Error("invalid_token", "Token revoked", null)
            );
        }

        return OAuth2TokenValidatorResult.success();
    }

}
