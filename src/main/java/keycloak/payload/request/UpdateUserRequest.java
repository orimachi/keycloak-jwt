package keycloak.payload.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.*;

@Builder
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserRequest {
    @NotBlank(message = "Username is required!")
    String username;

    @NotBlank(message = "Password is required!")
    String password;

    @NotBlank(message = "Email is required!")
    @Email(message = "Email is not valid!", regexp = "^[a-zA-Z0-9_!#$%&'*+/=?`{|}~^.-]+@[a-zA-Z0-9.-]+$")
    String email;

    @NotBlank(message = "Firstname is required!")
    String firstName;

    @NotBlank(message = "Lastname is required!")
    String lastName;
}
