package org.example.entity.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.example.security.enums.Roles;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Converter
public class RoleSetConverter implements AttributeConverter<Set<Roles>, String> {
	@Override
	public String convertToDatabaseColumn(Set<Roles> attribute) {
		if (attribute == null || attribute.isEmpty()) {
			return "";
		}
		return attribute.stream()
				.map(Enum::name)
				.collect(Collectors.joining(","));
	}

	@Override
	public Set<Roles> convertToEntityAttribute(String dbData) {
		if (dbData == null || dbData.isBlank()) {
			return Set.of();
		}
		return Arrays.stream(dbData.split(","))
				.map(String::trim)
				.map(Roles::valueOf)
				.collect(Collectors.toSet());
	}
}
