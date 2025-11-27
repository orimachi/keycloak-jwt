package keycloak.payload.request;

import lombok.*;

import java.util.List;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class RegisterUserRequest {
    String username;

    String password;

    String email;

    String firstName;

    String lastName;

    @Builder.Default
    Boolean emailVerify = false;

    List<String> roles;
}
