package com.jesussb.jwt_security_demo.common.auth;

import com.jesussb.jwt_security_demo.common.auth.dto.RevokeRequest;
import com.jesussb.jwt_security_demo.common.jwt.JwtService;
import com.jesussb.jwt_security_demo.common.auth.dto.LoginRequest;
import com.jesussb.jwt_security_demo.common.auth.dto.LoginResponse;
import com.jesussb.jwt_security_demo.common.jwt.JwtStore;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtStore jwtStore;

    @Override
    public LoginResponse login(LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        return new LoginResponse(
                jwtService.generate((
                        UserDetails) authentication.getPrincipal()
                )
        );
    }

    @Override
    public RevokeResponse revoke(RevokeRequest request) {

        Jwt jwt = jwtService.decode(request.token());

        String jti = jwt.getClaimAsString("jti");
        Instant exp = jwt.getExpiresAt();

        Duration duration = Duration.between(Instant.now(), exp);
        if (duration.isNegative() || duration.isZero()) {
            return new RevokeResponse("ok");
        }

        jwtStore.revoke(jti, duration);

        log.info("Revoked jwt token?: {}, {}", jti, jwtStore.isRevoked(jti));

        return new RevokeResponse("ok");
    }

}
