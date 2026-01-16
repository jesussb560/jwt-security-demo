package com.jesussb.jwt_security_demo.user;

import com.jesussb.jwt_security_demo.role.Role;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashSet;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserDetailServiceTest {

    @InjectMocks
    private UserDetailService userDetailService;

    @Mock
    private UserRepository userRepository;

    @Test
    void loadUserByUsername() {

        Role userRole = new Role();
        userRole.setName("USER");

        var roles = new HashSet<Role>();
        roles.add(userRole);

        when(userRepository.findUserByUsername(anyString())).thenReturn(Optional.of(User.builder()
                        .id(1L)
                        .username("username")
                        .password("password")
                        .roles(roles)
                .build()));

        AppUserDetails userDetails = (AppUserDetails) userDetailService.loadUserByUsername("username");

        assertThat(userDetails.getUsername()).isEqualTo("username");
        assertThat(userDetails.getPassword()).isEqualTo("password");
        assertThat(userDetails.getAuthorities()).hasSize(1);
        assertThat(userDetails.getAuthorities().iterator().next().getAuthority()).isEqualTo("ROLE_USER");
        assertThat(userDetails.getId()).isEqualTo(1L);

    }

    @Test
    void loadUserByUsernameNotFoundException() {

        when(userRepository.findUserByUsername(anyString())).thenReturn(Optional.empty());

        Exception exception = assertThrows(UsernameNotFoundException.class, () -> userDetailService.loadUserByUsername("username"));

        assertThat(exception).isInstanceOf(UsernameNotFoundException.class);
        assertThat(exception.getMessage()).isEqualTo("User not found with username: username");

    }

}