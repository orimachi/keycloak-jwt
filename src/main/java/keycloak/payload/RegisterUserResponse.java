package keycloak.payload;

import lombok.*;

import java.util.List;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RegisterUserResponse {
    String id;

    String username;

    String email;

    List<String> roles;
}
