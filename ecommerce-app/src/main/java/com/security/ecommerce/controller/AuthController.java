package com.security.ecommerce.controller;

import com.security.ecommerce.model.User;
import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    @Autowired
    private UserService userService;
    
    @Autowired
    private SecurityEventService securityEventService;

    // --- FIX: This method was missing, causing the 404 error ---
    @GetMapping("/login")
    public String login() {
        return "login"; // This looks for login.html in templates folder
    }
    // ----------------------------------------------------------

    @GetMapping("/register")
    public String showRegistrationForm() {
        return "register";
    }

    @PostMapping("/register")
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