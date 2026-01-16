package com.jesussb.jwt_security_demo.refreshtoken;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;

@Service
@RequiredArgsConstructor
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public String generate(Long userId) {

        String generatedToken = generateOpaqueToken();
        String hashedToken = encodeSha256(generatedToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(hashedToken)
                .revoked(false)
                .userId(userId)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plus(Duration.ofDays(15)))
                .build();

        refreshTokenRepository.save(refreshToken);

        return generatedToken;
    }

    @Override
    public RefreshToken validate(String token) {

        String hash = encodeSha256(token);
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new RuntimeException("Token not found"));

        if (refreshToken.isRevoked() || Instant.now().isAfter(refreshToken.getExpiresAt())) {
            throw new RuntimeException("Token not valid");
        }

        return refreshToken;
    }

    @Override
    public String rotate(String hash) {

        RefreshToken currentToken = refreshTokenRepository.findByTokenHash(hash)
                .orElseThrow(() -> new RuntimeException("Token not found"));

        currentToken = currentToken.toBuilder()
                .revoked(true)
                .rotatedAt(Instant.now())
                .build();

        refreshTokenRepository.save(currentToken);

        String generatedToken = generateOpaqueToken();
        String hashedToken = encodeSha256(generatedToken);

        RefreshToken refreshToken = RefreshToken.builder()
                .tokenHash(hashedToken)
                .revoked(false)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plus(Duration.ofDays(15)))
                .build();

        return refreshTokenRepository.save(refreshToken).getTokenHash();
    }

    private String generateOpaqueToken() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String encodeSha256(String token) {
        try {
            var md =  MessageDigest.getInstance("SHA-256");
            byte[] bytes = md.digest(token.getBytes());
            return HexFormat.of().formatHex(bytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
