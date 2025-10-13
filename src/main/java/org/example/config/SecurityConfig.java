package org.example.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.example.entity.User;
import org.example.repositories.UserRepository;
import org.example.security.JwtUtil;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Configuration
public class SecurityConfig {
    private final JwtUtil jwtUtil;
	private final UserRepository userRepo;

    public SecurityConfig(
			JwtUtil jwtUtil,
			UserRepository userRepo
    ) {
        this.jwtUtil = jwtUtil;
		this.userRepo = userRepo;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**", "/h2-console/**").permitAll()
                .anyRequest().authenticated()
            )
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin())) // enable H2 console
            .httpBasic(Customizer.withDefaults())
            .addFilterBefore(
					jwtFilter(),
		            UsernamePasswordAuthenticationFilter.class
            );

        return http.build();
    }

    public OncePerRequestFilter jwtFilter() {
        return new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse resp, FilterChain chain) throws ServletException, IOException {
                String h = req.getHeader(HttpHeaders.AUTHORIZATION);
                if (h != null && h.startsWith("Bearer ")) {
                    String token = h.substring(7);

                    try {
	                    User user = userRepo.findByAccessToken(token).orElseThrow(() -> new RuntimeException("Invalid Access token"));
	                    if (jwtUtil.isTokenExpired(token)) {
		                    throw new RuntimeException("Access token expired");
	                    }
	                    Jws<Claims> claims = jwtUtil.parseToken(token);
                        String subject = claims.getPayload().getSubject();
                        var auth = new UsernamePasswordAuthenticationToken(
								subject,
		                        null,
		                        List.of(
										new SimpleGrantedAuthority("ROLE_USER")
		                        )
                        );
                        auth.setDetails(user.getId());
                        SecurityContextHolder.getContext().setAuthentication(auth);
                    } catch (Exception e) {
                        // invalid token - ignore -> no auth
                    }
                }
                chain.doFilter(req, resp);
            }
        };
    }
}
