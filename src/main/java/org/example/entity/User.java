package org.example.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.example.constant.Socials;
import org.example.entity.converter.RoleSetConverter;
import org.example.security.enums.Roles;

import java.util.Set;

@Entity
@Table(
		name = "users",
		uniqueConstraints = {
			@UniqueConstraint(columnNames = {"provider", "providerId"})
        }
)
@Getter @Setter @NoArgsConstructor @AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // provider: google, facebook, apple, local
    @Column(nullable = false)
    @Enumerated(EnumType.STRING)
    private Socials provider;

    // provider id (e.g. sub) or email for local
    @Column(nullable = false)
    private String providerId;

    @Column(unique = true)
    private String email;

    private String name;

    // when provider == local
    private String passwordHash;

	@Column(unique = true, length = 512)
	private String refreshToken;

	@Column(unique = true, length = 512)
	private String accessToken;

	@Convert(converter = RoleSetConverter.class)
	private Set<Roles> roles = Set.of(Roles.USER);
}
