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
// product listing with basic input inspection
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
        
        // log suspicious image url values
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
        
        // log suspicious search values
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
    
    // validate urls and block known ssrf targets
    private boolean isSSRFAttempt(String url) {
        if (url == null || url.isBlank()) {
            return false;
        }
        
        String urlLower = url.toLowerCase();
        
        if (urlLower.startsWith("file://") || urlLower.startsWith("file:")) {
            return true;
        }
        
        if (!urlLower.startsWith("http://") && !urlLower.startsWith("https://")) {
            return true;
        }
        
        if (urlLower.contains("localhost") || 
            urlLower.contains("127.0.0.1") || 
            urlLower.contains("0.0.0.0") ||
            urlLower.contains("[::1]")) {
            return true;
        }
        
        if (urlLower.contains("169.254.169.254") ||
            urlLower.contains("169.254.170.2") ||
            urlLower.contains("metadata.google.internal")) {
            return true;
        }
        
        // block private ip ranges
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
