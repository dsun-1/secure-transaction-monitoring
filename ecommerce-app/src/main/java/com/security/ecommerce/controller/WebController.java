package com.security.ecommerce.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    @GetMapping("/")
    public String home() {
        return "index";
    }

    @GetMapping("/checkout")
    public String checkout() {
        return "checkout";
    }

    @GetMapping("/confirmation")
    public String confirmation() {
        return "confirmation";
    }
    
    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
