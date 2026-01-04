package com.security.ecommerce.controller;

import com.security.ecommerce.model.Product;import com.security.ecommerce.service.ProductService;import org.springframework.beans.factory.annotation.Autowired;import org.springframework.stereotype.Controller;import org.springframework.ui.Model;import org.springframework.web.bind.annotation.GetMapping;
import java.util.List;

import com.security.ecommerce.model.Product;import com.security.ecommerce.service.ProductService;import org.springframework.beans.factory.annotation.Autowired;import org.springframework.stereotype.Controller;import org.springframework.ui.Model;import org.springframework.web.bind.annotation.GetMapping;
import java.util.List;

@Controller
public class ProductController {

    @Autowired
    private ProductService productService;

    @GetMapping("/products")
    public String listProducts(Model model) {
        List<Product> products = productService.getAllProducts();
        model.addAttribute("products", products);
        return "products";
    }
    
    @GetMapping("/")
    public String home(Model model) {
        return listProducts(model); 
    }

}
