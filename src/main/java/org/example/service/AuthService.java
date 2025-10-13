package org.example.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.example.constant.Socials;
import org.example.dto.SocialUserInfo;
import org.example.entity.User;
import org.example.repositories.UserRepository;
import org.example.security.JwtUtil;
import org.springframework.core.env.Environment;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

import static org.example.constant.Socials.LOCAL;

@Service
public class AuthService {
    private final UserRepository userRepo;
    private final JwtUtil jwtUtil;
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final RestTemplate rest = new RestTemplate();
	private final Environment env;

    public AuthService(
			UserRepository userRepo,
			JwtUtil jwtUtil,
			Environment env
    ) {
        this.userRepo = userRepo;
        this.jwtUtil = jwtUtil;
		this.env = env;
    }

    /**
     * Social login:
     * - verify idToken with provider (simplified)
     * - create user if not exists
     * - generate access + refresh tokens, store refresh token
     */
    public Map<String, String> handleSocial(Socials provider, String idToken) {
        SocialUserInfo info = verifyWithProvider(provider, idToken);
        if (info == null) {
			throw new RuntimeException("Invalid provider token");
        }

        User user = userRepo.findByProviderAndProviderId(provider, info.getId())
                .orElseGet(() -> {
                    User u = new User();
                    u.setProvider(provider);
                    u.setProviderId(info.getId());
                    u.setEmail(info.getEmail());
                    u.setName(info.getName());
                    return userRepo.save(u);
                });

	    return  generateAndUpdateTokens(user);
    }

    /**
     * Email registration (local)
     */
    public Map<String,String> registerLocal(String email, String password, String name) {
        Optional<User> exists = userRepo.findByEmail(email);
        if (exists.isPresent()) throw new RuntimeException("Email already exists");
        User user = new User();
        user.setProvider(LOCAL);
        user.setProviderId(email);
        user.setEmail(email);
        user.setName(name);
        user.setPasswordHash(passwordEncoder.encode(password));
        userRepo.save(user);

	    return  generateAndUpdateTokens(user);
    }

    /**
     * Email login (local)
     */
    public Map<String,String> loginLocal(String email, String password) {
        User user = userRepo.findByEmail(email).orElseThrow(() -> new RuntimeException("Invalid credentials"));
        if (user.getProvider() != LOCAL) throw new RuntimeException("Not local user");
        if (!passwordEncoder.matches(password, user.getPasswordHash())) throw new RuntimeException("Invalid credentials");

	    return  generateAndUpdateTokens(user);
    }

    /**
     * Refresh flow: verify refreshToken exists and matches DB, then issue new access token
     */
    public Map<String,String> refreshAccess(String refreshToken) {
        if (jwtUtil.isTokenExpired(refreshToken)) {
			throw new RuntimeException("Refresh token expired");
        }

	    User user = userRepo
			    .findByRefreshToken(refreshToken)
			    .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

		return  generateAndUpdateTokens(user);
    }

	private Map<String, String> generateAndUpdateTokens(User user) {
		String access = jwtUtil.generateAccessToken(user);
		String refresh = jwtUtil.generateRefreshToken(user);

		user.setAccessToken(access);
		user.setRefreshToken(refresh);

		userRepo.save(user);

		return Map.of(
				"accessToken", access,
				"refreshToken", refresh
		);
	}

	/**
     * Logout - delete refresh token from DB
     */
    public void logout(String refreshToken) {
		User user = userRepo
				.findByRefreshToken(refreshToken)
				.orElseThrow(() -> new RuntimeException("Invalid refresh token for logout"));

		user.setAccessToken(null);
		user.setRefreshToken(null);
		userRepo.save(user);
    }

    /**
     * Very simplified provider verification.
     * For production use proper provider verification (Google tokeninfo or verifying JWT signature, Facebook Graph API, Apple JWKS).
     */
    private SocialUserInfo verifyWithProvider(Socials provider, String idToken) {
        switch (provider) {
	        case GOOGLE -> {
		        // validate using tokeninfo
		        String url = env.getProperty("google.api-url") + idToken;
		        Map resp = rest.getForObject(url, Map.class);
		        if (resp == null || resp.get("sub") == null) {
			        throw new RuntimeException("Google token validation failed");
		        }
		        return new SocialUserInfo((String)resp.get("sub"), (String)resp.get("email"), (String)resp.get("name"));
	        }
	        case FACEBOOK -> {
		        // Check token with Graph API
		        String debugUrl = env.getProperty("facebook.debug-url") +
				        "?input_token=" + idToken +
				        "&access_token=" + env.getProperty("facebook_app_id") + "|" + env.getProperty("facebook_app_secret");
		        // <-- app access token (APP_ID|APP_SECRET)
		        Map debugResp = rest.getForObject(debugUrl, Map.class);

		        if (debugResp == null || debugResp.get("data") == null) {
			        throw new RuntimeException("Invalid Facebook token");
		        }
		        Map data = (Map) debugResp.get("data");
		        if (!Boolean.TRUE.equals(data.get("is_valid"))) {
			        throw new RuntimeException("Invalid Facebook token");
		        }

		        // Get user profile
		        String userInfoUrl = env.getProperty("facebook.user-info-url") + idToken;
		        Map userResp = rest.getForObject(userInfoUrl, Map.class);
		        if (userResp == null || userResp.get("id") == null) {
			        throw new RuntimeException("Cannot fetch Facebook user info");
		        }

		        return new SocialUserInfo(
				        (String) userResp.get("id"),
				        (String) userResp.get("email"),
				        (String) userResp.get("name")
		        );
	        }
	        case APPLE -> {
		        try {
			        // Get public keys Apple
			        String keysUrl = env.getProperty("apple.api-url");
			        Map keysResponse = rest.getForObject(keysUrl, Map.class);
			        List<Map<String, String>> keys = (List<Map<String, String>>) keysResponse.get("keys");

			        //parse token and extract header
			        String[] parts = idToken.split("\\.");
			        if (parts.length < 2) {
						throw new RuntimeException("Invalid Apple ID token");
			        }

			        String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
			        ObjectMapper om = new ObjectMapper();
			        Map header = om.readValue(headerJson, Map.class);

			        String kid = (String) header.get("kid");
			        String alg = (String) header.get("alg");

			        // Find matched public key
			        Map<String, String> matchingKey = keys.stream()
					        .filter(k -> kid.equals(k.get("kid")) && alg.equals(k.get("alg")))
					        .findFirst()
					        .orElseThrow(() -> new RuntimeException("Apple public key not found"));

			        // Check token sign
			        RSAKey rsaKey = new RSAKey.Builder(new Base64URL(matchingKey.get("n")), new Base64URL(matchingKey.get("e")))
					        .keyID(kid)
					        .build();
			        SignedJWT signedJWT = SignedJWT.parse(idToken);
			        JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

			        if (!signedJWT.verify(verifier)) {
				        throw new RuntimeException("Invalid Apple token signature");
			        }

			        // Check token expiration
			        Date exp = signedJWT.getJWTClaimsSet().getExpirationTime();
			        if (exp.before(new Date())) {
				        throw new RuntimeException("Apple token expired");
			        }

			        // Extract user data
			        String sub = signedJWT.getJWTClaimsSet().getSubject();
			        String email = signedJWT.getJWTClaimsSet().getStringClaim("email");
			        String name = signedJWT.getJWTClaimsSet().getStringClaim("name");

			        return new SocialUserInfo(sub, email, name != null ? name : "Apple User");
		        } catch (Exception e) {
			        throw new RuntimeException("Apple token validation failed", e);
		        }
	        }
	        default ->  throw new RuntimeException("Invalid type of Auth provider");
        }
    }
}
