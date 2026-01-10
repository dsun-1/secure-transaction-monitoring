package com.security.ecommerce.controller;

import com.security.ecommerce.model.Product;
import com.security.ecommerce.service.ProductService;
import com.security.ecommerce.service.SecurityEventService;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Controller
public class ProductController {

    private final ProductService productService;
    private final SecurityEventService securityEventService;

    public ProductController(ProductService productService,
                             SecurityEventService securityEventService) {
        this.productService = productService;
        this.securityEventService = securityEventService;
    }

    @GetMapping("/products")
    public String listProducts(Model model,
                               @RequestParam(required = false) String search,
                               @RequestParam(required = false) String currency,
                               @RequestParam(required = false) String imageUrl) {
        List<Product> products = productService.getAllProducts();
        model.addAttribute("products", products);
        
        // Detect SSRF attempts in imageUrl parameter
        if (imageUrl != null && !imageUrl.isBlank()) {
            if (isSSRFAttempt(imageUrl)) {
                securityEventService.logHighSeverityEvent(
                    "SSRF_ATTEMPT",
                    "anonymous",
                    "SSRF pattern detected in imageUrl parameter",
                    "imageUrl=" + imageUrl
                );
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid image URL");
            }
        }
        
        // Detect SQL injection attempts in search parameter
        if (search != null && !search.isBlank()) {
            String searchLower = search.toLowerCase();
            if (searchLower.contains("'") || searchLower.contains("--") || 
                searchLower.contains("union") || searchLower.contains("select") ||
                searchLower.contains("drop") || searchLower.contains("insert") ||
                searchLower.contains("delete") || searchLower.contains("update") ||
                searchLower.contains(";")) {
                securityEventService.logHighSeverityEvent(
                    "SQL_INJECTION_ATTEMPT",
                    "anonymous",
                    "SQL injection pattern detected in search parameter",
                    "search=" + search
                );
            }
            
            // Detect XSS attempts in search parameter
            if (searchLower.contains("<script") || searchLower.contains("javascript:") ||
                searchLower.contains("onerror") || searchLower.contains("onload") ||
                searchLower.contains("<img") || searchLower.contains("<iframe")) {
                securityEventService.logHighSeverityEvent(
                    "XSS_ATTEMPT",
                    "anonymous",
                    "XSS pattern detected in search parameter",
                    "search=" + search
                );
            }
        }
        
        if (currency != null && !currency.isBlank()) {
            securityEventService.logHighSeverityEvent(
                "AMOUNT_TAMPERING",
                "anonymous",
                "Currency parameter supplied in product listing",
                "currency=" + currency
            );
        }
        return "products";
    }
    
    /**
     * Validates URL to prevent SSRF attacks
     * Blocks: file://, localhost, private IP ranges, cloud metadata endpoints
     */
    private boolean isSSRFAttempt(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        
        String urlLower = url.toLowerCase();
        
        // Block file:// protocol
        if (urlLower.startsWith("file://") || urlLower.startsWith("file:")) {
            return true;
        }
        
        // Block non-HTTP protocols
        if (!urlLower.startsWith("http://") && !urlLower.startsWith("https://")) {
            return true;
        }
        
        // Block localhost variants
        if (urlLower.contains("localhost") || 
            urlLower.contains("127.0.0.1") || 
            urlLower.contains("0.0.0.0") ||
            urlLower.contains("[::1]")) {
            return true;
        }
        
        // Block cloud metadata endpoints
        if (urlLower.contains("169.254.169.254") ||  // AWS/Azure metadata
            urlLower.contains("169.254.170.2") ||    // ECS task metadata
            urlLower.contains("metadata.google.internal")) {  // GCP metadata
            return true;
        }
        
        // Block private IP ranges
        // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        if (urlLower.matches(".*://10\\..*") ||
            urlLower.matches(".*://172\\.(1[6-9]|2[0-9]|3[0-1])\\..*") ||
            urlLower.matches(".*://192\\.168\\..*")) {
            return true;
        }
        
        return false;
    }
    
    @GetMapping("/")
    public String home(Model model) {
        return listProducts(model, null, null, null);
    }

}
