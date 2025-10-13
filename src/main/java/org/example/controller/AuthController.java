package org.example.controller;

import org.example.constant.Socials;
import org.example.service.AuthService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService svc;

    public AuthController(AuthService svc) {
        this.svc = svc;
    }

    @PostMapping("/social")
    public ResponseEntity<?> social(@RequestBody Map<String, String> body) {
        Socials provider = Socials.valueOf(body.get("provider").toUpperCase());
        String idToken = body.get("idToken");
        if (idToken == null) {
			return ResponseEntity.badRequest().body("provider and idToken required");
        }
        Map<String, String> tokens = svc.handleSocial(provider, idToken);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/email/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        String name = body.getOrDefault("name", "");
        if (email == null || password == null) return ResponseEntity.badRequest().body("email/password required");
        Map<String, String> tokens = svc.registerLocal(email, password, name);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/email/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        String password = body.get("password");
        if (email == null || password == null) return ResponseEntity.badRequest().body("email/password required");
        Map<String, String> tokens = svc.loginLocal(email, password);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String,String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null) return ResponseEntity.badRequest().body("refreshToken required");
        Map<String,String> tokens = svc.refreshAccess(refreshToken);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String,String> body) {
        String refreshToken = body.get("refreshToken");
        if (refreshToken == null) return ResponseEntity.badRequest().body("refreshToken required");
        svc.logout(refreshToken);
        return ResponseEntity.ok(Map.of("status", "ok"));
    }
}
