package com.insy2s.KeyCloakAuth.controller;


import com.insy2s.KeyCloakAuth.dto.ChangePasswordRequest;
import com.insy2s.KeyCloakAuth.model.LoginRequest;
import com.insy2s.KeyCloakAuth.model.LoginResponse;
import com.insy2s.KeyCloakAuth.service.LoginService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/keycloak/auth")
public class LoginController {
@Autowired
private RestTemplate restTemplate;

	@Autowired
	LoginService loginservice;
	
	@PostMapping("/login")
	public ResponseEntity<LoginResponse> login (@RequestBody LoginRequest loginrequest) {

		return loginservice.login(loginrequest);
		


	}

		@PostMapping("/changePassword")
		public ResponseEntity<?> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest, HttpServletRequest httpServletRequest) {
			String authorizationHeader = httpServletRequest.getHeader("Authorization");
			String token = null;
			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				token = authorizationHeader.substring(7); // Remove "Bearer " prefix
			}
				return loginservice.changePassword(changePasswordRequest,token);

		}


	@PostMapping("/logout")
		public ResponseEntity<String> logout (HttpServletRequest httpServletRequest ,@RequestBody String tokenRefrech) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication != null) {
			String authorizationHeader = httpServletRequest.getHeader("Authorization");
			String token = null;
			if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
				token = authorizationHeader.substring(7); // Remove "Bearer " prefix
			}

			return loginservice.logout(token,tokenRefrech);


		}
			return ResponseEntity.status(500).body("Eroor ");
		}
	@PostMapping("/forgotPassword")
	public ResponseEntity<String> forgotPassword  (@RequestBody ChangePasswordRequest request) {


			return loginservice.forgotPassword(request);
	}

}



