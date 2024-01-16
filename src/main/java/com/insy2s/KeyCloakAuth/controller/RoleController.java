package com.insy2s.KeyCloakAuth.controller;

import com.insy2s.KeyCloakAuth.model.Role;
import com.insy2s.KeyCloakAuth.service.RoleService;
import org.keycloak.representations.idm.RoleRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/keycloak/roles")
public class RoleController {
    @Autowired
    private RoleService roleService;
    @GetMapping("/test")
    String test( )
    {
        return "hello";
    }
    @GetMapping("/")
    List<Role> getRole( )
    {
        return roleService.getRoles( );
    }
    @PostMapping("/")
    ResponseEntity create(Role role )
    {
        return roleService.createUser( role);
    }

}
