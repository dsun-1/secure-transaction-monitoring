package com.security.ecommerce.controller;

import com.security.ecommerce.model.CartItem;
import com.security.ecommerce.service.CartService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.math.BigDecimal;
import java.util.List;

@Controller
@RequestMapping("/cart")
public class CartController {

    @Autowired
    private CartService cartService;

    @GetMapping
    public String viewCart(HttpSession session, Model model) {
        String sessionId = session.getId();
        List<CartItem> cartItems = cartService.getCartItems(sessionId);
        BigDecimal total = cartService.getCartTotal(sessionId);
        
        model.addAttribute("cartItems", cartItems);
        model.addAttribute("total", total);
        
        return "cart";
    }

    @PostMapping("/add")
    public String addToCart(@RequestParam Long productId,
                           @RequestParam(defaultValue = "1") Integer quantity,
                           HttpSession session) {
        String sessionId = session.getId();
        cartService.addToCart(sessionId, productId, quantity);
        
        return "redirect:/products";
    }

    @PostMapping("/update")
    public String updateCart(@RequestParam Long cartItemId,
                            @RequestParam Integer quantity,
                            HttpSession session) {
        String sessionId = session.getId();
        cartService.updateQuantity(sessionId, cartItemId, quantity);
        return "redirect:/cart";
    }

    @PostMapping("/remove")
    public String removeFromCart(@RequestParam Long cartItemId,
                                HttpSession session) {
        String sessionId = session.getId();
        cartService.removeFromCart(sessionId, cartItemId);
        return "redirect:/cart";
    }

    @PostMapping("/clear")
    public String clearCart(HttpSession session) {
        String sessionId = session.getId();
        cartService.clearCart(sessionId);
        return "redirect:/cart";
    }
}
