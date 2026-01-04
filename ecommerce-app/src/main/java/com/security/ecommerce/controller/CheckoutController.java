package com.security.ecommerce.controller;

import com.security.ecommerce.model.CartItem;
import com.security.ecommerce.model.Transaction;
import com.security.ecommerce.model.User;
import com.security.ecommerce.service.CartService;
import com.security.ecommerce.service.TransactionService;
import com.security.ecommerce.service.UserService;
import jakarta.servlet.http.HttpSession;
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
// checkout flow; this is a key surface for tampering and fraud tests
public class CheckoutController {

    private final CartService cartService;
    private final TransactionService transactionService;
    private final UserService userService;

    public CheckoutController(CartService cartService,
                              TransactionService transactionService,
                              UserService userService) {
        this.cartService = cartService;
        this.transactionService = transactionService;
        this.userService = userService;
    }

    @GetMapping("/checkout")
    // renders checkout details and total for the current session cart
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
            
            model.addAttribute("loggedIn", true);
        }
        
        return "checkout";
    }

    @PostMapping("/checkout/process")
    // processes payment submission and creates a transaction record
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
        
        
        if (cardNumber == null || cardNumber.length() < 13) {
            model.addAttribute("error", "Invalid card number");
            model.addAttribute("cartItems", cartItems);
            model.addAttribute("total", total);
            return "checkout";
        }
        
        
        User user = username != null ? userService.findByUsername(username) : null;
        
        try {
            Transaction transaction = transactionService.createTransaction(
                user, 
                total, 
                cardNumber.substring(cardNumber.length() - 4), 
                shippingAddress
            );
            
            
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
