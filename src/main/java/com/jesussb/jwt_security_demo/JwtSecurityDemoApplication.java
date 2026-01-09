package com.jesussb.jwt_security_demo;

import com.jesussb.jwt_security_demo.role.Role;
import com.jesussb.jwt_security_demo.role.RoleRepository;
import com.jesussb.jwt_security_demo.user.User;
import com.jesussb.jwt_security_demo.user.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootApplication
public class JwtSecurityDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtSecurityDemoApplication.class, args);
	}

	@Bean
	public CommandLineRunner commandLineRunner(UserRepository repository, PasswordEncoder passwordEncoder, RoleRepository roleRepository) {
		return args -> {

			Role adminRole = new Role();
			adminRole.setName("ADMIN");
			Role userRole = new Role();
			userRole.setName("USER");
			roleRepository.saveAll(List.of(adminRole, userRole));

			User admin = new User();
			admin.setUsername("admin");
			admin.addRole(adminRole);
			admin.setPassword(passwordEncoder.encode("admin"));

			User user = new User();
			user.setUsername("user");
			user.addRole(userRole);
			user.setPassword(passwordEncoder.encode("user"));

			repository.saveAll(List.of(admin, user));
		};
	}

}
