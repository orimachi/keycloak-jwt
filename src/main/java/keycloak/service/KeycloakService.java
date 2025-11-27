package keycloak.service;

import jakarta.ws.rs.core.Response;
import keycloak.enums.ERole;
import keycloak.exception.CustomException;
import keycloak.payload.dto.UserDTO;
import keycloak.payload.request.RegisterUserRequest;
import keycloak.payload.response.RegisterUserResponse;
import keycloak.payload.request.UpdateUserRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class KeycloakService {
    private final Keycloak keycloak;

    @Value("${spring.keycloak.realm-name}")
    private String realmName;

    private boolean isUsernameExist(UsersResource resource, String username){
        List<UserRepresentation> users = resource.search(username,true);
        return users.stream().anyMatch(UserRepresentation::isEnabled);
    }

    private boolean isEmailExist(UsersResource resource, String email){
        List<UserRepresentation> users = resource.searchByEmail(email,true);
        return users.stream().anyMatch(UserRepresentation::isEnabled);
    }

    private void assignRolesToUser(UserResource userResource, RealmResource realmResource, List<String> roleName){
        try {
            List<RoleRepresentation> availableRoles = realmResource.roles().list();

            List<RoleRepresentation> rolesToAssign = availableRoles.stream().filter(role -> roleName.contains(role.getName())).toList();

            if (rolesToAssign.isEmpty()) {
                log.warn("Cant find any roles in list {}. Please create roles in Keycloak first", roleName);
                throw new CustomException("Cant find roles: " + roleName);
            }

            userResource.roles().realmLevel().add(rolesToAssign);
            log.info("Role:{}", roleName);
        } catch (Exception e){
            log.error("Error when assign roles: {}", e.getMessage(), e);
            throw new CustomException("Error when assign roles for user: " + e.getMessage());

        }
    }

    public RegisterUserResponse registerUser(RegisterUserRequest request){
        try {
            RealmResource realmResource = keycloak.realm(realmName);
            UsersResource usersResource = realmResource.users();

            if (isUsernameExist(usersResource,request.getUsername())){
                log.error("Username already exist");
                throw new CustomException("Username already exist");
            }

            if (isEmailExist(usersResource,request.getEmail())){
                log.error("Email already exist");
                throw new CustomException("Email already exist");
            }

            UserRepresentation userRepresentation = new UserRepresentation();
            userRepresentation.setUsername(request.getUsername());
            userRepresentation.setEmail(request.getEmail());
            userRepresentation.setFirstName(request.getFirstName());
            userRepresentation.setLastName(request.getLastName());
            userRepresentation.setEnabled(true);
            userRepresentation.setEmailVerified(request.getEmailVerify());

            Response response = usersResource.create(userRepresentation);

            if (response.getStatus() != 201){
                String errorMessage = response.readEntity(String.class);
                log.error("Cant create user. Status: {}, Error: {}", response.getStatus(), errorMessage);
                throw new CustomException("Cant create user: " + errorMessage);
            }

            String userId = response.getLocation().getPath().substring(response.getLocation().getPath().lastIndexOf("/") + 1);
            log.info("User create with id:{}" , userId);

            UserResource userResource = usersResource.get(userId);
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(request.getPassword());
            credential.setTemporary(false);
            userResource.resetPassword(credential);

            List<String> rolesToAssign = request.getRoles() != null && !request.getRoles().isEmpty() ? request.getRoles() : Collections.singletonList(ERole.USER.toString());

            assignRolesToUser(userResource,realmResource,rolesToAssign);

            response.close();

            return RegisterUserResponse.builder().id(userId).username(request.getUsername()).email(request.getEmail()).roles(rolesToAssign).build();
        } catch (Exception e){
            throw new CustomException("Error when register user", e);
        }
    }

    public UserDTO getUserByUsername(String username){
        try {
            List<UserRepresentation> users = keycloak.realm(realmName).users().search(username, true);

            if (users.isEmpty()) {
                throw new CustomException("User with username " + username + " not exist");
            }

            UserRepresentation rep = users.getFirst();

            UserResource userResource = keycloak.realm(realmName).users().get(rep.getId());

            List<String> roles = userResource.roles()
                    .realmLevel()
                    .listAll()
                    .stream()
                    .map(RoleRepresentation::getName)
                    .toList();

            return UserDTO.builder()
                    .id(rep.getId())
                    .username(rep.getUsername())
                    .email(rep.getEmail())
                    .firstName(rep.getFirstName())
                    .lastName(rep.getLastName())
                    .realmRoles(roles)
                    .build();

        } catch (Exception e) {
            log.error("Error when find user: {}", e.getMessage(), e);
            throw new CustomException("Error when find user: " + e.getMessage());
        }
    }

    public UserRepresentation updateUser(UpdateUserRequest request, String userId) {
        try {
            if (userId == null){
                throw new CustomException("UserId is required!");
            }

            UserResource userResource = keycloak.realm(realmName).users().get(userId);
            UserRepresentation user = userResource.toRepresentation();

            if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
                List<UserRepresentation> users = keycloak.realm(realmName).users()
                        .search(null, null, null, request.getEmail(), 0, 1);

                if (!users.isEmpty() && !users.getFirst().getId().equals(userId)) {
                    throw new CustomException("Email already exists");
                }
            }

            if (request.getUsername() != null) user.setUsername(request.getUsername());
            if (request.getFirstName() != null) user.setFirstName(request.getFirstName());
            if (request.getLastName() != null) user.setLastName(request.getLastName());
            if (request.getEmail() != null) {
                user.setEmail(request.getEmail());
                user.setEmailVerified(false);
            }

            if (request.getPassword() != null) {
                CredentialRepresentation credential = new CredentialRepresentation();
                credential.setTemporary(false);
                credential.setType(CredentialRepresentation.PASSWORD);
                credential.setValue(request.getPassword());
                userResource.resetPassword(credential);
            }

            userResource.update(user);
            log.info("Update user with ID: {}", userId);

            return userResource.toRepresentation();
        } catch (Exception e) {
            log.error("Error when update user: {}", e.getMessage(), e);
            throw new CustomException("Error when update user: " + e.getMessage());
        }
    }

    public void deleteUser(String userId) {
        try {
            keycloak.realm(realmName).users().get(userId).remove();
            log.info("Delete user with ID: {}", userId);
        } catch (Exception e) {
            log.error("Error when delete user: {}", e.getMessage(), e);
            throw new CustomException("Error when delete user: " + e.getMessage());
        }
    }
}
