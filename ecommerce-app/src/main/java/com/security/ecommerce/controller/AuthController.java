package com.security.ecommerce.controller;

import com.security.ecommerce.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
// auth entry points; these are high-value attack surfaces for credential abuse
public class AuthController {

    private final UserService userService;

    public AuthController(UserService userService) {
        this.userService = userService;
    }

    
    @GetMapping("/login")
    // serves login page used by auth and brute-force tests
    public String login() {
        return "login"; 
    }
    

    @GetMapping("/register")
    // serves registration form for new users
    public String showRegistrationForm() {
        return "register";
    }

    @PostMapping("/register")
    // registration flow that persists users and surfaces errors
    public String registerUser(@RequestParam String username, 
                             @RequestParam String email,
                             @RequestParam String password,
                             Model model) {
        try {
            userService.registerUser(username, email, password);
            return "redirect:/login?registered";
        } catch (Exception e) {
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "register";
        }
    }
}
