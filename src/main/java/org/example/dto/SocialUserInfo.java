package org.example.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class SocialUserInfo {
    private String id;
	private String email;
	private String name;
}