package com.security.ecommerce.controller;

import com.security.ecommerce.model.CartItem;
import com.security.ecommerce.model.Transaction;
import com.security.ecommerce.model.User;
import com.security.ecommerce.service.CartService;
import com.security.ecommerce.service.TransactionService;
import com.security.ecommerce.service.UserService;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.math.BigDecimal;
import java.util.List;

@Controller
public class CheckoutController {

    @Autowired
    private CartService cartService;

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private UserService userService;

    @GetMapping("/checkout")
    public String checkoutPage(HttpSession session, Model model) {
        String sessionId = session.getId();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean isAuthenticated = authentication != null
            && authentication.isAuthenticated()
            && !(authentication instanceof AnonymousAuthenticationToken);
        
        List<CartItem> cartItems = cartService.getCartItems(sessionId);
        BigDecimal total = cartService.getCartTotal(sessionId);
        
        if (cartItems.isEmpty()) {
            return "redirect:/cart";
        }
        
        model.addAttribute("cartItems", cartItems);
        model.addAttribute("total", total);
        
        if (isAuthenticated) {
            // User is logged in - could pre-fill shipping info
            model.addAttribute("loggedIn", true);
        }
        
        return "checkout";
    }

    @PostMapping("/checkout/process")
    public String processCheckout(@RequestParam String cardNumber,
                                  @RequestParam String cardName,
                                  @RequestParam String expiryDate,
                                  @RequestParam String cvv,
                                  @RequestParam(required = false) String shippingAddress,
                                  HttpSession session,
                                  Model model) {
        
        String sessionId = session.getId();
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication != null ? authentication.getName() : null;
        
        List<CartItem> cartItems = cartService.getCartItems(sessionId);
        BigDecimal total = cartService.getCartTotal(sessionId);
        
        if (cartItems.isEmpty()) {
            return "redirect:/cart";
        }
        
        // Validate payment (basic validation)
        if (cardNumber == null || cardNumber.length() < 13) {
            model.addAttribute("error", "Invalid card number");
            model.addAttribute("cartItems", cartItems);
            model.addAttribute("total", total);
            return "checkout";
        }
        
        // Create transaction
        User user = username != null ? userService.findByUsername(username) : null;
        
        try {
            Transaction transaction = transactionService.createTransaction(
                user, 
                total, 
                cardNumber.substring(cardNumber.length() - 4), // Last 4 digits
                shippingAddress
            );
            
            // Clear cart after successful checkout
            cartService.clearCart(sessionId);
            
            model.addAttribute("transaction", transaction);
            model.addAttribute("transactionId", transaction.getId());
            
            return "confirmation";
            
        } catch (Exception e) {
            model.addAttribute("error", "Payment processing failed: " + e.getMessage());
            model.addAttribute("cartItems", cartItems);
            model.addAttribute("total", total);
            return "checkout";
        }
    }
}
