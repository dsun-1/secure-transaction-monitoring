package com.security.ecommerce.controller;

import com.security.ecommerce.model.CartItem;
import com.security.ecommerce.model.Transaction;
import com.security.ecommerce.model.User;
import com.security.ecommerce.service.CartService;
import com.security.ecommerce.service.SecurityEventService;
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
import java.util.Objects;

@Controller
// checkout flow; this is a key surface for tampering and fraud tests
public class CheckoutController {

    private final CartService cartService;
    private final TransactionService transactionService;
    private final UserService userService;
    private final SecurityEventService securityEventService;

    public CheckoutController(CartService cartService,
                              TransactionService transactionService,
                              UserService userService,
                              SecurityEventService securityEventService) {
        this.cartService = cartService;
        this.transactionService = transactionService;
        this.userService = userService;
        this.securityEventService = securityEventService;
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
                                  @RequestParam(required = false) String clientTotal,
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
        
        String validationError = null;
        if (cardNumber == null || cardNumber.length() < 13) {
            validationError = "Invalid card number";
        } else if (cardName == null || cardName.isBlank()) {
            validationError = "Cardholder name is required";
        } else if (expiryDate == null || !expiryDate.matches("\\d{2}/\\d{2}")) {
            validationError = "Invalid expiry date";
        } else if (cvv == null || !cvv.matches("\\d{3,4}")) {
            validationError = "Invalid CVV";
        } else if (shippingAddress != null
                && !shippingAddress.isBlank()
                && shippingAddress.trim().length() < 10) {
            validationError = "Shipping address is too short";
        }
        
        if (validationError != null) {
            model.addAttribute("error", validationError);
            model.addAttribute("cartItems", cartItems);
            model.addAttribute("total", total);
            return "checkout";
        }

        if (clientTotal != null && !clientTotal.isBlank()) {
            try {
                BigDecimal submittedTotal = new BigDecimal(clientTotal.trim());
                if (submittedTotal.compareTo(total) != 0) {
                    String usernameLabel = username != null ? username : "anonymous";
                    securityEventService.logHighSeverityEvent(
                        "AMOUNT_TAMPERING",
                        usernameLabel,
                        "Checkout total mismatch detected",
                        "client_total=" + submittedTotal + " | server_total=" + total
                    );
                    securityEventService.recordTransactionAnomaly(
                        "CLIENT_TOTAL_MISMATCH",
                        usernameLabel,
                        "CLIENT_TOTAL_MISMATCH",
                        total.doubleValue(),
                        submittedTotal.doubleValue(),
                        "Client total did not match server total"
                    );
                }
            } catch (NumberFormatException ex) {
                securityEventService.logHighSeverityEvent(
                    "AMOUNT_TAMPERING",
                    username != null ? username : "anonymous",
                    "Invalid checkout total submitted",
                    "client_total=" + clientTotal
                );
            }
        }
        
        
        User user = username != null ? userService.findByUsername(username) : null;
        
        try {
            Objects.requireNonNull(cardNumber, "Card number is required");
            String last4 = cardNumber.substring(cardNumber.length() - 4);
            Transaction transaction = transactionService.createTransaction(
                user,
                total,
                last4
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
