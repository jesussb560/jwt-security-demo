package com.jesussb.jwt_security_demo.common.jwt;

import com.jesussb.jwt_security_demo.user.AppUserDetails;
import com.jesussb.jwt_security_demo.user.User;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class JwtServiceIntegrationTest {

    @Test
    void generateAndDecode() throws NoSuchAlgorithmException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaJwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaJwk));
        JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
        JwtDecoder decoder = NimbusJwtDecoder.withPublicKey(publicKey).build();

        JwtService service = new JwtService(encoder, decoder);

        var userDetails = new AppUserDetails(
                1L,
                "username",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        String token = service.generate(userDetails);
        Jwt jwt = service.decode(token);

        assertThat(jwt.getSubject()).isEqualTo("username");
        assertThat(jwt.getClaimAsStringList("roles")).containsExactlyInAnyOrder("ROLE_USER");
        assertThat(jwt.getClaimAsString("jti")).isNotBlank();
        assertThat(jwt.getIssuedAt()).isBefore(jwt.getExpiresAt());
        assertThat(jwt.getExpiresAt()).isAfter(Instant.now());

    }

}