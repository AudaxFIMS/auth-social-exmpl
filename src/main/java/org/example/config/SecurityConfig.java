package org.example.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.example.entity.User;
import org.example.repositories.UserRepository;
import org.example.security.JwtUtil;
import org.example.service.UserAuthoritiesService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    private final JwtUtil jwtUtil;
	private final UserRepository userRepo;
	private final UserAuthoritiesService securityUser;

    public SecurityConfig(
			JwtUtil jwtUtil,
			UserRepository userRepo,
			UserAuthoritiesService userAuthoritiesService
    ) {
        this.jwtUtil = jwtUtil;
		this.userRepo = userRepo;
		this.securityUser = userAuthoritiesService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/auth/**", "/h2-console/**").permitAll()
                .anyRequest().authenticated()
            )
            .headers(
					headers ->
							headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin)
            ) // enable H2 console
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
	                    if (jwtUtil.isTokenExpired(token)) {
		                    throw new IllegalArgumentException("Access token expired");
	                    }
	                    User user = userRepo.findByAccessToken(token)
			                    .orElseThrow(() -> new IllegalArgumentException("Invalid Access token"));

	                    Jws<Claims> claims = jwtUtil.parseToken(token);
                        String subject = claims.getPayload().getSubject();
                        var auth = new UsernamePasswordAuthenticationToken(
								subject,
		                        null,
		                        securityUser.getUserAuthorities(user)
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
