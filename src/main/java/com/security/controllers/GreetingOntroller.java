package com.security.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController

public class GreetingOntroller {

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/user")
    public String greetUser(){
        return "Hello User";

    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String greetAdmin(){
        return "Hello Admin";

    }
}
