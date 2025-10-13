package org.example.repositories;

import org.example.constant.Socials;
import org.example.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByProviderAndProviderId(Socials provider, String providerId);
    Optional<User> findByEmail(String email);
	Optional<User> findByRefreshToken(String refreshToken);
	Optional<User>  findByAccessToken(String token);
}
