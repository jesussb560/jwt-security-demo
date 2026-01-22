package com.jesussb.jwt_security_demo.common.auth;

import com.jesussb.jwt_security_demo.common.auth.dto.*;
import com.jesussb.jwt_security_demo.common.jwt.JwtService;
import com.jesussb.jwt_security_demo.common.jwt.JwtStore;
import com.jesussb.jwt_security_demo.refreshtoken.RefreshToken;
import com.jesussb.jwt_security_demo.refreshtoken.RefreshTokenService;
import com.jesussb.jwt_security_demo.user.AppUserDetails;
import com.jesussb.jwt_security_demo.user.User;
import com.jesussb.jwt_security_demo.user.UserDetailService;
import com.jesussb.jwt_security_demo.user.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @InjectMocks
    private AuthServiceImpl authServiceImpl;

    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private Clock clock;
    @Mock
    private JwtService jwtService;
    @Mock
    private RefreshTokenService refreshTokenService;
    @Mock
    private UserDetailService userDetailService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtStore jwtStore;

    @Test
    void login(){

        Authentication authentication = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(authentication);

        when(authentication.getPrincipal()).thenReturn(new AppUserDetails(
                1L,
                "username",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        ));

        when(jwtService.generate(any())).thenReturn("token");
        when(refreshTokenService.generate(any())).thenReturn("refreshToken");

        LoginResponse response = authServiceImpl.login(new LoginRequest("username", "password"));
        assertThat(response).isNotNull();
        assertThat(response.token()).isEqualTo("token");
        assertThat(response.refreshToken()).isEqualTo("refreshToken");

    }

    @Test
    void loginPrincipalException(){

        doThrow(BadCredentialsException.class).when(authenticationManager).authenticate(any());
        assertThrows(BadCredentialsException.class, () -> authServiceImpl.login(new LoginRequest("username", "password")));

    }

    @Test
    void revoke(){

        when(clock.instant()).thenReturn(Instant.now());

        Jwt jwt = Jwt
                .withTokenValue("abc")
                .header("alg", "none")
                .claim("jti", "abc")
                .expiresAt(Instant.now().plusSeconds(5))

                .build();

        when(jwtService.decode("abc")).thenReturn(jwt);

        RevokeResponse response = authServiceImpl.revoke(new RevokeRequest("abc"));
        verify(jwtStore).revoke(anyString(),any());
        assertThat(response).isNotNull();
        assertThat(response.status()).isEqualTo("ok");

    }

    @Test
    void revokeExpired(){

        when(clock.instant()).thenReturn(Instant.now());

        Jwt jwt = Jwt
                .withTokenValue("abc")
                .header("alg", "none")
                .claim("jti", "abc")
                .expiresAt(Instant.now().minusSeconds(5))

                .build();

        when(jwtService.decode("abc")).thenReturn(jwt);

        RevokeResponse response = authServiceImpl.revoke(new RevokeRequest("abc"));
        verify(jwtStore, times(0)).revoke(anyString(),any());
        assertThat(response).isNotNull();
        assertThat(response.status()).isEqualTo("ok (expired)");

    }

    @Test
    void refresh(){

        when(refreshTokenService.validate(anyString())).thenReturn(RefreshToken.builder()
                        .userId(1L)
                .build());
        when(userRepository.findById(anyLong())).thenReturn(Optional.of(User.builder().username("username").build()));
        when(userDetailService.loadUserByUsername(anyString())).thenReturn(new AppUserDetails(
                1L,
                "username",
                "password",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        ));

        when(jwtService.generate(any())).thenReturn("token");
        when(refreshTokenService.rotate(any())).thenReturn("refreshToken");

        RefreshResponse response = authServiceImpl.refresh(new RefreshRequest("token"));
        assertThat(response).isNotNull();
        assertThat(response.token()).isEqualTo("token");
        assertThat(response.refreshToken()).isEqualTo("refreshToken");


    }

}