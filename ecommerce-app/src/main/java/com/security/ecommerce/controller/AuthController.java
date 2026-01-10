package com.security.ecommerce.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
// auth entry points; these are high-value attack surfaces for credential abuse
public class AuthController {

    
    @GetMapping("/login")
    // serves login page used by auth and brute-force tests
    public String login() {
        return "login"; 
    }
}
