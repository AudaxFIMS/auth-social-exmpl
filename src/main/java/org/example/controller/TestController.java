package org.example.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

	@PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/test/admin-role/protected")
    public String protectedAdminEndpoint(@AuthenticationPrincipal String username) {
        return "Hello, " + username + " — this is protected for admin only";
    }

	@PreAuthorize("hasAnyAuthority('ADMIN','USER')")
	@GetMapping("/test/any-role/protected")
	public String protectedAnyEndpoint(@AuthenticationPrincipal String username) {
		return "Hello, " + username + " — this is protected for any roles";
	}
}
