package keycloak.payload;

import lombok.*;

import java.util.List;

@Builder
@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class FindUserByUsernameResponse<T> {
    T result;

    List<String> roles;
}
