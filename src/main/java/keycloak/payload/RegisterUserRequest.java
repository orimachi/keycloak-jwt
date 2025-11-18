package keycloak.payload;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Builder
@Getter
@Setter
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
