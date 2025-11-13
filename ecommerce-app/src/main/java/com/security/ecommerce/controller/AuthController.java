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

    // ...existing code...
}
