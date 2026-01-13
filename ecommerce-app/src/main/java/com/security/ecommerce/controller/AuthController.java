package com.security.ecommerce.controller;

import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import jakarta.servlet.http.HttpServletRequest;

@Controller
// auth endpoints for login and registration
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final UserService userService;
    private final SecurityEventService securityEventService;
    private final boolean demoMode;

    public AuthController(UserService userService,
                          SecurityEventService securityEventService,
                          @Value("${security.demo-mode:false}") boolean demoMode) {
        this.userService = userService;
        this.securityEventService = securityEventService;
        this.demoMode = demoMode;
    }

    @GetMapping("/login")
    // render the login view
    public String login(Model model) {
        model.addAttribute("demoMode", demoMode);
        return "login"; 
    }
    

    @GetMapping("/register")
    // render the registration view
    public String showRegistrationForm() {
        return "register";
    }

    @PostMapping("/register")
    // handle registration and surface errors in the view
    public String registerUser(@RequestParam String username, 
                             @RequestParam String email,
                             @RequestParam String password,
                             @RequestParam(required = false) String honeypot_field,
                             Model model,
                             HttpServletRequest request) {
        if (honeypot_field != null && !honeypot_field.isBlank()) {
            securityEventService.logHighSeverityEvent(
                "BOT_REGISTRATION_ATTEMPT",
                "bot-detected",
                "Honeypot field populated during registration",
                "ip=" + request.getRemoteAddr() + " | value=" + honeypot_field
            );
            return "redirect:/login?registered";
        }
        try {
            userService.registerUser(username, email, password);
            return "redirect:/login?registered";
        } catch (Exception e) {
            logger.warn("Registration failed for {}", username, e);
            model.addAttribute("error", "Registration failed. Please check your details and try again.");
            return "register";
        }
    }
}
