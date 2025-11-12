package com.security.ecommerce.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class WebController {

    // Removed @GetMapping("/") - now handled by ProductController

    @GetMapping("/confirmation")
    public String confirmation() {
        return "confirmation";
    }
}
