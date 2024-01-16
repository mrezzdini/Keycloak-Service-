package com.insy2s.KeyCloakAuth.config;

import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.client.RestTemplate;

@KeycloakConfiguration
public  class SecurityConfig   {

	@Bean
	public RestTemplate restTemplate(RestTemplateBuilder builder) {
		return builder.build();
	}


	@Bean
	public KeycloakSpringBootConfigResolver keycloakConfigResolver() {
		return new KeycloakSpringBootConfigResolver();
	}

	@Bean
	protected DefaultSecurityFilterChain configure(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests()
				.requestMatchers("/api/keycloak/auth/login")
				.permitAll()
				.requestMatchers("/api/keycloak/auth/forgotPassword")
				.permitAll()
				.anyRequest()
				.authenticated();

		http.csrf().disable()
				.oauth2ResourceServer()
				.jwt();
		return http.build();}




	@Bean
	protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
		return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
	}

}
