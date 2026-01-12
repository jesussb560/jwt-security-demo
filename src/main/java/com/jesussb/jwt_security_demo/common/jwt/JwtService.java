package com.jesussb.jwt_security_demo.common.jwt;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    public String generate(UserDetails userDetails) {

        List<String> roles = userDetails.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        Instant now = Instant.now();
        var claims = Map.of(
                "roles", roles,
                "jti", UUID.randomUUID().toString()
        );

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("issuer")
                .subject(userDetails.getUsername())
                .expiresAt(now.plus(Duration.ofHours(24)))
                .issuedAt(now)
                .claims(c -> c.putAll(claims))
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .build();

        return jwtEncoder.encode(
                JwtEncoderParameters.from(header, claimsSet)
        ).getTokenValue();

    }

    public Jwt decode(String token) {
        return jwtDecoder.decode(token);
    }

}
