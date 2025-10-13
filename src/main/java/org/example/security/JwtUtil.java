package org.example.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.example.entity.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {
    private final SecretKey key;
    private final long accessTokenExpirySec;
    private final long refreshTokenExpirySec;

    public JwtUtil(@Value("${security.jwt.secret}") String secret,
                   @Value("${security.jwt.access-token-expiration-sec}") long accessTokenExpirySec,
                   @Value("${security.jwt.refresh-token-expiration-sec}") long refreshTokenExpirySec) {
        // secret must be long enough for HMAC-SHA
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.accessTokenExpirySec = accessTokenExpirySec;
        this.refreshTokenExpirySec = refreshTokenExpirySec;
    }

    public String generateAccessToken(User user) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(user.getEmail())
                .claim("userId", user.getId())
                .issuedAt(new Date(now))
                .expiration(new Date(now + accessTokenExpirySec * 1000))
                .signWith(key)
                .compact();
    }

    public String generateRefreshToken(User user) {
        long now = System.currentTimeMillis();
        return Jwts.builder()
                .subject(user.getEmail())
                .issuedAt(new Date(now))
                .expiration(new Date(now + refreshTokenExpirySec * 1000))
                .signWith(key)
                .compact();
    }

    public Jws<Claims> parseToken(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token);
    }

    public boolean isTokenExpired(String token) {
        try {
            Date exp = parseToken(token).getPayload().getExpiration();
            return exp.before(new Date());
        } catch (JwtException e) {
            return true;
        }
    }
}
