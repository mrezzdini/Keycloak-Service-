package com.insy2s.KeyCloakAuth.dto;

import lombok.Data;
import org.keycloak.representations.idm.CredentialRepresentation;

@Data
public class ChangePasswordRequest {
    private String userId;
    private String oldPassword;
    private String newPassword;
    private String username;


    public CredentialRepresentation toRepresentation() {
        CredentialRepresentation credential = new CredentialRepresentation();
        credential.setType("password");
        credential.setValue(newPassword);
        credential.setTemporary(false);

        return credential;
    }

}