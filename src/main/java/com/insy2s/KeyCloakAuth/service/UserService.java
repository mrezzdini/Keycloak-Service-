package com.insy2s.KeyCloakAuth.service;

import com.insy2s.KeyCloakAuth.GedClient.GedClient;
import com.insy2s.KeyCloakAuth.dto.UserDto;
import com.insy2s.KeyCloakAuth.model.*;
import com.insy2s.KeyCloakAuth.repository.RoleRepository;
import com.insy2s.KeyCloakAuth.repository.UserRepository;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.security.SecureRandom;
import java.util.*;


@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private RoleService roleService;
    @Autowired
    private GedClient gedClient;
    @Autowired
    RestTemplate restTemplate;
    @Autowired
    private LoginService loginService;
    @Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
    private String issueUrl;

    @Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-id}")
    private String clientId;
    @Value("${uri-user}")
    private String issueUrlUser;
    private static final String KEYCLOAK_URL = "https://keycloak.fethi.synology.me/auth";
    private static final String REALM_NAME = "KeyClock-INSY2S";
    public ResponseEntity<String> deleteUser(String id, String jwt) {
        System.out.println(id);
        HttpHeaders headers = new HttpHeaders();

        MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
        map.add("client_id", clientId);
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBearerAuth(jwt);

        HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, headers);

        ResponseEntity<Response> responseEntity = restTemplate.exchange(
                KEYCLOAK_URL + "/admin/realms/" + REALM_NAME + "/users/" + id,
                HttpMethod.DELETE,
                httpEntity,
                Response.class
        );
        System.out.println(responseEntity.getStatusCode()==HttpStatus.NO_CONTENT);
        // Check the response status
        if (responseEntity.getStatusCode()==HttpStatus.NO_CONTENT) {
            User userSearched = userRepository.findById(id).orElse(null);
            if (userSearched != null) {
                userRepository.delete(userSearched);
            }
            return ResponseEntity.status(HttpStatus.OK).body("L'utilisateur "+userSearched.getUsername()+" supprimé avec success.");
        } else {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Échec de la suppression de l'utilisateur.");
        }
    }

    public static String generateRandomPassword() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder sb = new StringBuilder();
        SecureRandom random = new SecureRandom();

        int length = 30; // Longueur du mot de passe souhaitée

        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(characters.length());
            char randomChar = characters.charAt(randomIndex);
            sb.append(randomChar);
        }

        return sb.toString();
    }

    public ResponseEntity createUser(UserDto user) {
        Role role = roleRepository.findByName(user.getRole()).get();
        System.out.println(role);
        System.out.println(user.getRole());
        User userSaved = new User();
        Collection<Role> roles = new ArrayList<>();
        roles.add(role);

        String randomPassword = generateRandomPassword();
        System.out.println("password" + randomPassword);
        user.setPassword(randomPassword);
        LoginRequest loginRequest = new LoginRequest("insy2s", "insy2s");
        ResponseEntity<LoginResponse> token = loginService.login(loginRequest);

        HttpHeaders headersuser = new HttpHeaders();
        headersuser.setBearerAuth(token.getBody().getAccess_token());

        UserRepresentation userRepresentation = new UserRepresentation();
        userRepresentation.setFirstName(user.getFirstname());
        userRepresentation.setLastName(user.getLastname());
        userRepresentation.setEmail(user.getEmail());
        userRepresentation.setUsername(user.getUsername());
        userRepresentation.setCredentials(Collections.singletonList(getPasswordCredentials(user.getPassword())));
        userRepresentation.setEnabled(true);
        userRepresentation.setEmailVerified(true);
        userRepresentation.setRealmRoles(List.of("roleName"));
        HttpEntity<UserRepresentation> request = new HttpEntity<>(userRepresentation, headersuser);
        String userUrl = issueUrlUser + "/users/";
        URI uri = UriComponentsBuilder.fromUriString(userUrl).buildAndExpand("KeyClock-INSY2S").toUri();
        String userSearchedFromKeycloak = getUserByIdFromKeycloak(user.getUsername());
        if (Objects.equals(userSearchedFromKeycloak, null)) {
            ResponseEntity<UserRepresentation> response =
                    restTemplate.postForEntity(uri, request, UserRepresentation.class
                    );

            if (response.getStatusCode().value() == 201) {
                String userSearchedFromKeycloak1 = getUserByIdFromKeycloak(user.getUsername());

                user.setId(userSearchedFromKeycloak1);
                userSaved.setId(user.getId());
                userSaved.setFirstname(user.getFirstname());
                userSaved.setUsername(user.getUsername());
                userSaved.setLastname(user.getLastname());
                userSaved.setEmail(user.getEmail());
                userSaved.setPassword(user.getPassword());
                userSaved.setRoles(roles);
                userRepository.save(userSaved);

            }
            return ResponseEntity.status(201).body(userSaved);
        } else {


            return ResponseEntity.status(302).body(" user found");
        }

    }


    private CredentialRepresentation getPasswordCredentials(String password) {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType(CredentialRepresentation.PASSWORD);
        credential.setValue(password);
        credential.setTemporary(false);
        return credential;
    }

    public String getUserByIdFromKeycloak(String username) {
        String id= null;

        try {
            LoginRequest loginRequest = new LoginRequest("insy2s", "insy2s");
            ResponseEntity<LoginResponse> tokenResponse = loginService.login(loginRequest);
            String accessToken = tokenResponse.getBody().getAccess_token();

            // Set the Authorization header with the access token
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(accessToken);
            HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

            // Build the user URL with the provided username
            String userApiUrl = issueUrlUser + "/users/";
            URI uri = UriComponentsBuilder.fromUriString(userApiUrl)
                    .queryParam("username", username)
                    .build()
                    .toUri();

            // Send the GET request to Keycloak and retrieve the user representation
            ResponseEntity<UserRepresentation[]> response = restTemplate.exchange(uri, HttpMethod.GET, requestEntity, UserRepresentation[].class);
            if (response.getStatusCode().is2xxSuccessful()) {
                UserRepresentation[] userRepresentations = response.getBody();
                if (userRepresentations != null && userRepresentations.length > 0) {
                    UserRepresentation userRepresentation = userRepresentations[0];
                    id = userRepresentation.getId();

                    // Map other necessary fields from userRepresentation to userSearchedFromKeycloak
                }
            }
        } catch (Exception e) {
            // Handle the exception or return a default value
            e.printStackTrace();
        }

        return id;
    }




    public User getUser(String username) {
        return userRepository.findByUsername(username).get();
    }

    public ResponseEntity listUsers() {
        return ResponseEntity.status(200).body(userRepository.findAll());
    }

    public ResponseEntity desActiveUser(String username) {
        LoginRequest loginRequest = new LoginRequest("insy2s", "insy2s");
        ResponseEntity<LoginResponse> token = loginService.login(loginRequest);

        HttpHeaders headersuser = new HttpHeaders();
        headersuser.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headersuser.setBearerAuth(token.getBody().getAccess_token());
        HttpEntity<?> httpEntityuser = new HttpEntity<>(headersuser);
        String userUrl = issueUrlUser + "/users/"; // replace {realm} with your realm name
        URI uri = UriComponentsBuilder.fromUriString(userUrl).buildAndExpand("KeyClock-INSY2S").toUri();

        ParameterizedTypeReference<List<UserRepresentation>> responseType = new ParameterizedTypeReference<>() {
        };
        ResponseEntity<List<UserRepresentation>> responseUser = restTemplate.exchange(uri, HttpMethod.PUT, httpEntityuser, responseType);
        List<UserRepresentation> userList = responseUser.getBody();
        return ResponseEntity.ok(userList);
    }
}
