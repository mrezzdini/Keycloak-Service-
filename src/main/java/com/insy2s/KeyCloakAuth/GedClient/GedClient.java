package com.insy2s.KeyCloakAuth.GedClient;


import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;

@FeignClient(value = "GedService", url = "http://localhost:8090/api/file")

public interface GedClient {


    @PostMapping("/")
    String saveProfilPhoto(@RequestBody MultipartFile multipartFile
            ,@RequestParam String nameFolder,
                           @RequestHeader("Authorization") String bearerToken
    );

}