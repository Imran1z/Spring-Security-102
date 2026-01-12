package com.security.jwt;

import lombok.*;

import java.util.List;

@Data
@Getter
@Setter
@RequiredArgsConstructor
@NoArgsConstructor
@AllArgsConstructor
public class LoginResponse {
    private String jwtToken;
    private String username;
    private List<String > Roles;

}
