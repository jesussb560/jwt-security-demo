package com.jesussb.jwt_security_demo.common.jwt;

import com.jesussb.jwt_security_demo.user.AppUserDetails;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    @Mock
    private JwtEncoder jwtEncoder;
    @Mock
    private JwtDecoder jwtDecoder;

    @Captor
    ArgumentCaptor<JwtEncoderParameters> paramsCaptor;

    @Test
    void generate() throws IOException {

        var userDetails = new AppUserDetails(
                1L,
                "username",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        when(jwtEncoder.encode(any(JwtEncoderParameters.class)))
                .thenReturn(Jwt.withTokenValue("token-value")
                        .header("alg", "RS256")
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(3600))
                        .build()
                );

        String response = jwtService.generate(userDetails);

        assertThat(response).isEqualTo("token-value");

        verify(jwtEncoder).encode(paramsCaptor.capture());
        JwtEncoderParameters params = paramsCaptor.getValue();

        JwsHeader header = params.getJwsHeader();
        JwtClaimsSet claims = params.getClaims();

        assertThat(header.getAlgorithm()).isEqualTo(SignatureAlgorithm.RS256);
        assertThat(claims.getSubject()).isEqualTo("username");
        assertThat(claims.getClaimAsString("jti")).isNotBlank();
        assertThat(claims.getClaimAsStringList("roles"))
                .containsExactlyInAnyOrder("ROLE_USER");

    }

    @Test
    void decode() {

        Jwt jwt = Jwt.withTokenValue("abc").header("alg", "none").claim("k", "v").build();
        when(jwtDecoder.decode("abc")).thenReturn(jwt);

        Jwt result = jwtService.decode("abc");

            assertThat(result).isSameAs(jwt);
        verify(jwtDecoder).decode("abc");
        verifyNoMoreInteractions(jwtDecoder);
    }
}