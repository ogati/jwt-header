package ca.gc.aafc.employee.api.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import ca.gc.aafc.employee.api.auth.JwtFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
	
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
    
	@Bean
    SecurityFilterChain filterChain(HttpSecurity http, JwtFilter jwtFilter, Environment env) throws Exception {
		List<String> publicUrls = new ArrayList<>(List.of("/index.html", "/login", "/employees.html"));
		
		if (env.matchesProfiles("dev")) {
    		publicUrls.add("/h2-console/**");
    		http.headers(headers -> headers.frameOptions(frame -> frame.disable()));
		}
		
        http.csrf(csrf -> csrf.disable())
        	.sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> 
            	auth.requestMatchers(publicUrls.toArray(String[]::new)).permitAll()
	                .requestMatchers("/admin/**").hasRole("ADMIN")
	                .anyRequest().authenticated())
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
		
        return http.build();
    }
	
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
