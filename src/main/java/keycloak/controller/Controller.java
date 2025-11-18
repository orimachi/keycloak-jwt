package keycloak.controller;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import keycloak.exception.CustomException;
import keycloak.payload.*;
import keycloak.service.KeycloakService;
import keycloak.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/")
@RequiredArgsConstructor
public class Controller {
    private final KeycloakService keycloakService;
    private final TokenService tokenService;
    @PostMapping("register")
    public APIResponse<Object> registerUser(@Valid @RequestBody RegisterUserRequest request){
        RegisterUserResponse response = keycloakService.registerUser(request);
        return APIResponse.builder().result(response).message("Register user API").build();
    }

    @PutMapping("update")
    public APIResponse<Object> updateUser(@Valid @RequestBody UpdateUserRequest request){
        UserRepresentation response = keycloakService.updateUser(request);
        return APIResponse.builder().result(response).message("Update user API").build();
    }

    @DeleteMapping("delete")
    public APIResponse<Object> deleteUser(String userId){
        // find way to delete without id
        keycloakService.deleteUser(userId);
        return APIResponse.builder().message("Delete user API").build();
    }

    @GetMapping("me/{username}")
    public APIResponse<Object> getUserByUsername(@PathVariable @NotBlank(message = "Username is required for this API") String username){
        FindUserByUsernameResponse<Object> response = keycloakService.getUserByUsername(username);
        return APIResponse.builder().result(response).message("Get user by username API").build();
    }

    @PostMapping("/internal-token")
    public APIResponse<Object> generatedInternalAccessToken(@RequestBody LoginRequest request){
        KeycloakTokenResponse keycloakTokenResponse = tokenService.getTokenKeycloak(request);
        if (!tokenService.introspectKeyCloakToken(keycloakTokenResponse.getAccessToken())){
            throw new CustomException("Invalid access token from keycloak");
        }
        String internalToken = tokenService.generateInternalTokenFromKeycloak(keycloakTokenResponse.getAccessToken());
        return APIResponse.builder().result(internalToken).message("Internal Token").build();
    }
}
