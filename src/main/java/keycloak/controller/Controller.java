package keycloak.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import keycloak.exception.CustomException;
import keycloak.payload.dto.UserDTO;
import keycloak.payload.request.LoginRequest;
import keycloak.payload.request.RegisterUserRequest;
import keycloak.payload.request.UpdateUserRequest;
import keycloak.payload.response.APIResponse;
import keycloak.payload.response.KeycloakTokenResponse;
import keycloak.payload.response.RegisterUserResponse;
import keycloak.service.KeycloakService;
import keycloak.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/")
@RequiredArgsConstructor
@Tag(name = "controller", description = "Controller class")
public class Controller {
    private final KeycloakService keycloakService;
    private final TokenService tokenService;
    @PostMapping("register")
    @Operation(method = "POST", summary = "Register User", description = "register new user")
    public APIResponse<Object> registerUser(@Valid @RequestBody RegisterUserRequest request){
        RegisterUserResponse response = keycloakService.registerUser(request);
        return APIResponse.builder().message("Register user API").result(response).build();
    }

    @PutMapping("update")
    @Operation(method = "PUT", summary = "Update user", description = "update user need role USER")
    @PreAuthorize("hasRole('USER')")
    public APIResponse<Object> updateUser(@Valid @RequestBody UpdateUserRequest updateUserRequest, HttpServletRequest request){
        String token = request.getHeader("Authorization").substring(7);
        String userId = tokenService.getClaim(token,"ClientId");
        UserRepresentation response = keycloakService.updateUser(updateUserRequest,userId);
        return APIResponse.builder().message("Update user API").result(response).build();
    }

    @DeleteMapping("delete")
    @Operation(method = "DELETE", summary = "Delete user", description = "delete user need role USER")
    @PreAuthorize("hasRole('USER')")
    public APIResponse<Object> deleteUser(HttpServletRequest request){
        String token = request.getHeader("Authorization").substring(7);
        String userId = tokenService.getClaim(token,"ClientId");
        keycloakService.deleteUser(userId);
        return APIResponse.builder().message("Delete user API").build();
    }

    @GetMapping("me")
    @PreAuthorize("hasRole('USER')")
    public APIResponse<Object> getUserByUsername(@Parameter(description = "username user keycloak", required = true, example = "john") @RequestParam(name = "username") @NotBlank(message = "Username is required for this API") String username){
        UserDTO response = keycloakService.getUserByUsername(username);
        return APIResponse.builder().message("Get user by username API").result(response).build();
    }

    @PostMapping("/internal-token")
    @Operation(method = "POST",summary = "Get internal access token", description = "get internal access token")
    public APIResponse<Object> generatedInternalAccessToken(@RequestBody LoginRequest request){
        KeycloakTokenResponse keycloakTokenResponse = tokenService.getTokenKeycloak(request);
        if (!tokenService.introspectKeyCloakToken(keycloakTokenResponse.getAccessToken())){
            throw new CustomException("Invalid access token from keycloak");
        }
        String internalToken = tokenService.generateInternalTokenFromKeycloak(keycloakTokenResponse.getAccessToken());
        return APIResponse.builder().message("Internal Token").result(internalToken).build();
    }
}
