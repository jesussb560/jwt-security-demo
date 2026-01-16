package com.jesussb.jwt_security_demo.common.auth;

import com.jesussb.jwt_security_demo.common.auth.dto.*;
import com.jesussb.jwt_security_demo.common.jwt.JwtService;
import com.jesussb.jwt_security_demo.common.jwt.JwtStore;
import com.jesussb.jwt_security_demo.refreshtoken.RefreshToken;
import com.jesussb.jwt_security_demo.refreshtoken.RefreshTokenRepository;
import com.jesussb.jwt_security_demo.refreshtoken.RefreshTokenService;
import com.jesussb.jwt_security_demo.user.AppUserDetails;
import com.jesussb.jwt_security_demo.user.User;
import com.jesussb.jwt_security_demo.user.UserDetailService;
import com.jesussb.jwt_security_demo.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;
    private final RefreshTokenService  refreshTokenService;
    private final UserDetailService userDetailService;
    private final UserRepository userRepository;

    private final JwtStore jwtStore;

    @Override
    public LoginResponse login(LoginRequest request) {

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.username(),
                        request.password()
                )
        );

        AppUserDetails principal = (AppUserDetails) authentication.getPrincipal();

        return new LoginResponse(
                jwtService.generate(principal),
                refreshTokenService.generate(principal.getId())
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

    @Override
    public RefreshResponse refresh(RefreshRequest request) {

        RefreshToken validated = refreshTokenService.validate(request.refreshToken());

        User user = userRepository.findById(validated.getUserId()).orElseThrow(() -> new RuntimeException("Invalid user id " + validated.getUserId()));
        AppUserDetails principal = (AppUserDetails) userDetailService.loadUserByUsername(user.getUsername());

        return new RefreshResponse(
                jwtService.generate(principal),
                refreshTokenService.rotate(validated.getTokenHash())
        );
    }


}
