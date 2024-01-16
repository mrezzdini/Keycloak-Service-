package com.insy2s.KeyCloakAuth.controller;

import com.insy2s.KeyCloakAuth.dto.UserDto;
import com.insy2s.KeyCloakAuth.model.User;
import com.insy2s.KeyCloakAuth.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/keycloak/users")
public class UserController {
    @Autowired
    private UserService userService;
    @GetMapping("/test")
    String test( )
    {
        return "hello";
    }
    @GetMapping("/find")
    ResponseEntity<User> getUser(@RequestParam String username )
    {
        return ResponseEntity.status(200).body(userService.getUser(username ));
    }
    @GetMapping("/")
    ResponseEntity getAllUsers( )
    {
        return userService.listUsers( );
    }
//    @GetMapping("/tesst")
//    List<UserRepresentation> test( )
//    {
//        return userService.test( );
//    }
    @PostMapping(value = "/")
    ResponseEntity createUser(@RequestBody UserDto user){

        return userService.createUser( user);
    }
    @PutMapping(value = "/")
    ResponseEntity desActiveUser(@RequestParam String username){

        return userService.desActiveUser( username);
    }
    @DeleteMapping(value = "/{id}")
    ResponseEntity deleteUser(@PathVariable String id , HttpServletRequest httpServletRequest){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            String authorizationHeader = httpServletRequest.getHeader("Authorization");
            String token = null;
            if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
                token = authorizationHeader.substring(7); // Remove "Bearer " prefix
            }
        return userService.deleteUser( id,token);
    }
        return ResponseEntity.status(500).body("Eroor ");
    }}


