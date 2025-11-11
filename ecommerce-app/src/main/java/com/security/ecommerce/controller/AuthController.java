package com.security.ecommerce.controller;

import com.security.ecommerce.model.User;
import com.security.ecommerce.service.SecurityEventService;
import com.security.ecommerce.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
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

    @GetMapping("/login")
    public String loginPage(@RequestParam(required = false) String error, 
                           @RequestParam(required = false) String logout, 
                           Model model) {
        if (error != null) {
            model.addAttribute("error", "Invalid username or password");
        }
        if (logout != null) {
            model.addAttribute("message", "You have been logged out successfully");
        }
        return "login";
    }

    @PostMapping("/perform_login")
    public String performLogin(@RequestParam String username,
                              @RequestParam String password,
                              HttpServletRequest request,
                              HttpSession session,
                              Model model) {
        
        String ipAddress = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");
        
        User user = userService.authenticate(username, password);
        
        if (user != null) {
            // Successful login
            session.setAttribute("userId", user.getId());
            session.setAttribute("username", user.getUsername());
            session.setAttribute("userRole", user.getRole());
            
            securityEventService.logAuthenticationAttempt(username, ipAddress, true, userAgent);
            
            return "redirect:/products";
        } else {
            // Failed login
            securityEventService.logAuthenticationAttempt(username, ipAddress, false, userAgent);
            
            model.addAttribute("error", "Invalid username or password");
            return "login";
        }
    }

    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login?logout=true";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                          @RequestParam String email,
                          @RequestParam String password,
                          Model model) {
        
        if (userService.findByUsername(username) != null) {
            model.addAttribute("error", "Username already exists");
            return "register";
        }
        
        User user = userService.registerUser(username, email, password);
        
        if (user != null) {
            model.addAttribute("message", "Registration successful! Please login.");
            return "login";
        } else {
            model.addAttribute("error", "Registration failed");
            return "register";
        }
    }
}
