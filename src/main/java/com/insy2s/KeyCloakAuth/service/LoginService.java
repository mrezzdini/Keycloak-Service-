package com.insy2s.KeyCloakAuth.service;


import com.insy2s.KeyCloakAuth.dto.ChangePasswordRequest;
import com.insy2s.KeyCloakAuth.model.LoginRequest;
import com.insy2s.KeyCloakAuth.model.LoginResponse;
import com.insy2s.KeyCloakAuth.model.Response;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

@Service
public class LoginService {

	@Autowired
	RestTemplate restTemplate;
	private static final String KEYCLOAK_URL = "https://keycloak.fethi.synology.me/auth";
	private static final String REALM_NAME = "KeyClock-INSY2S";
	@Value("${spring.security.oauth2.client.provider.keycloak.token-uri}")
	private String issueUrl;
	@Value("${uri-user}")
	private String urlusers;
	@Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-id}")
	private String clientId;
	
	@Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.client-secret}")
	private String clientSecret;
	
	@Value("${spring.security.oauth2.client.registration.oauth2-client-credentials.authorization-grant-type}")
	private String grantType;


	public ResponseEntity<LoginResponse> login(LoginRequest loginrequest) {
		try {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("client_id", clientId);
		map.add("client_secret", clientSecret);
		map.add("grant_type", grantType);
		map.add("username", loginrequest.getUsername());
		map.add("password", loginrequest.getPassword());
		
		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map,headers);
		
		ResponseEntity<LoginResponse> response = restTemplate.postForEntity(issueUrl, httpEntity, LoginResponse.class);
			if (response.getStatusCode().is2xxSuccessful()) {
				LoginResponse loginResponse = response.getBody();
		return  ResponseEntity.status(200).body(response.getBody());
		} else {
			// Gérer le cas où la demande de connexion échoue
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
		}
	} catch (HttpClientErrorException.BadRequest e) {
		// Gérer les erreurs de demande incorrecte (400)
		return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
	} catch (HttpClientErrorException.Unauthorized e) {
		// Gérer les erreurs d'authentification non autorisée (401)
		return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(null);
	} catch (Exception e) {
		// Gérer toutes les autres exceptions
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(null);
	}
	}
	public ResponseEntity<String> logout(String jwt, String tokenRefresh) {
		HttpHeaders headers = new HttpHeaders();

		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		map.add("grant_type", grantType);
		map.add("client_id", clientId);
		map.add("refresh_token", tokenRefresh);
		map.add("client_secret", clientSecret);

		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setBearerAuth(jwt);

		HttpEntity<MultiValueMap<String, String>> httpEntity = new HttpEntity<>(map, headers);

		ResponseEntity<Response> responseEntity = restTemplate.exchange(
				"https://keycloak.fethi.synology.me/auth/realms/KeyClock-INSY2S/protocol/openid-connect/logout",
				HttpMethod.POST,
				httpEntity,
				Response.class
		);

		if (responseEntity.getStatusCode() == HttpStatus.NO_CONTENT) {
			return ResponseEntity.ok("Déconnexion réussie merci de votre confiance !");
		} else {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
		}
	}


	public ResponseEntity<?> changePassword(ChangePasswordRequest changePasswordRequest, String jwt) {
		System.out.println(changePasswordRequest.getUserId());
		System.out.println(changePasswordRequest.getUsername());
		System.out.println(changePasswordRequest.getOldPassword());
		System.out.println(changePasswordRequest.getNewPassword());

		String userId = changePasswordRequest.getUserId();
		String oldPassword = changePasswordRequest.getOldPassword();
		String newPassword = changePasswordRequest.getNewPassword();

		// Test de connexion avec l'ancien nom d'utilisateur et le mot de passe
		LoginRequest loginRequest = new LoginRequest(changePasswordRequest.getUsername(), oldPassword);
		ResponseEntity<LoginResponse> loginResponse = login(loginRequest);

		if (loginResponse.getStatusCode().is2xxSuccessful()) {
			// Connexion réussie, changer le mot de passe
			CredentialRepresentation newCredential = toCredentialRepresentation(newPassword);
			String updateUserUrl = urlusers + "/users/" + userId + "/reset-password";

			HttpHeaders headers = new HttpHeaders();
			headers.setBearerAuth(jwt);
			headers.setContentType(MediaType.APPLICATION_JSON);

			HttpEntity<CredentialRepresentation> updateRequest = new HttpEntity<>(newCredential, headers);

			try {
				// Configuration de RestTemplate
				RestTemplate restTemplate = new RestTemplate();

				ResponseEntity<String> updateResponse = restTemplate.exchange(
						updateUserUrl,
						HttpMethod.PUT,
						updateRequest,
						String.class
				);

				if (updateResponse.getStatusCode().is2xxSuccessful()) {
					return ResponseEntity.ok().body("Mot de passe changé avec succès.");
				} else {
					return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Erreur lors du changement de mot de passe.");
				}
			} catch (HttpClientErrorException ex) {
				// Gérer les erreurs HTTP
				System.out.println("Erreur lors de la modification du mot de passe : " + ex.getMessage());
				return ResponseEntity.status(ex.getStatusCode()).body("Erreur lors de la modification du mot de passe : " + ex.getMessage());
			} catch (Exception ex) {
				// Gérer les autres exceptions
				System.out.println("Une erreur s'est produite : " + ex.getMessage());
				return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Une erreur s'est produite lors de la modification du mot de passe.");
			}
		} else {
			return ResponseEntity.badRequest().body("L'ancien nom d'utilisateur ou le mot de passe est incorrect.");
		}
	}

	private CredentialRepresentation toCredentialRepresentation(String password) {
		CredentialRepresentation credential = new CredentialRepresentation();
		credential.setType(CredentialRepresentation.PASSWORD);
		credential.setValue(password);
		credential.setTemporary(false);
		return credential;
	}


	public ResponseEntity<String> forgotPassword(@RequestBody ChangePasswordRequest request) {
		LoginRequest loginRequest = new LoginRequest("insy2s", "insy2s");
		LoginResponse loginResponse = login(loginRequest).getBody();
		HttpHeaders headers = new HttpHeaders();
		headers.setBearerAuth(loginResponse.getAccess_token());
		HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

		// Find the user by username
		ResponseEntity<UserRepresentation[]> response = restTemplate.exchange(
				urlusers + "/users?username=" + request.getUsername(),
				HttpMethod.GET,
				requestEntity,
				UserRepresentation[].class
		);

		if (response.getStatusCode().is2xxSuccessful()) {
			UserRepresentation[] userRepresentations = response.getBody();
			if (userRepresentations != null && userRepresentations.length > 0) {
				UserRepresentation userRepresentation = userRepresentations[0];
				// Update the user's password
				CredentialRepresentation newCredential = toCredentialRepresentation(request.getNewPassword());
				userRepresentation.setCredentials(Collections.singletonList(newCredential));

				String updateUserUrl = urlusers + "/users/" + userRepresentation.getId();
				HttpHeaders updateUserHeaders = new HttpHeaders();
				updateUserHeaders.setBearerAuth(loginResponse.getAccess_token());
				updateUserHeaders.setContentType(MediaType.APPLICATION_JSON);
				HttpEntity<UserRepresentation> updateUserRequest = new HttpEntity<>(userRepresentation, updateUserHeaders);
				ResponseEntity<Void> updateUserResponse = restTemplate.exchange(
						updateUserUrl,
						HttpMethod.PUT,
						updateUserRequest,
						Void.class
				);

				if (updateUserResponse.getStatusCode().is2xxSuccessful()) {
					return ResponseEntity.ok().body("Password update successful.");
				} else {
					return ResponseEntity.badRequest().body("Password update failed.");
				}
			}
		}
		return ResponseEntity.status(404).body("User not found") ;
	}}






