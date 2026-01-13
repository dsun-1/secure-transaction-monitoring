package com.security.ecommerce.controller;

import com.security.ecommerce.model.CartItem;
import com.security.ecommerce.service.CartService;
import com.security.ecommerce.service.SecurityEventService;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.math.BigDecimal;
import java.util.List;

@Controller
@RequestMapping("/cart")
// session-scoped cart operations with tampering signals
public class CartController {

    private final CartService cartService;
    private final SecurityEventService securityEventService;

    public CartController(CartService cartService,
                          SecurityEventService securityEventService) {
        this.cartService = cartService;
        this.securityEventService = securityEventService;
    }

    @GetMapping
    // render the cart for the current session
    public String viewCart(HttpSession session, Model model) {
        String sessionId = session.getId();
        List<CartItem> cartItems = cartService.getCartItems(sessionId);
        BigDecimal total = cartService.getCartTotal(sessionId);
        
        model.addAttribute("cartItems", cartItems);
        model.addAttribute("total", total);
        
        return "cart";
    }

    @PostMapping("/add")
    // add items and log suspicious client parameters
    public String addToCart(@RequestParam Long productId,
                           @RequestParam(defaultValue = "1") Integer quantity,
                           HttpSession session,
                           HttpServletRequest request) {
        String sessionId = session.getId();
        if (quantity == null || quantity <= 0) {
            securityEventService.logHighSeverityEvent(
                "CART_MANIPULATION",
                "anonymous",
                "Invalid cart quantity submitted",
                "quantity=" + quantity
            );
        }
        if (request.getParameter("price") != null || request.getParameter("total") != null) {
            securityEventService.logHighSeverityEvent(
                "CART_MANIPULATION",
                "anonymous",
                "Unexpected pricing parameters submitted",
                "params=" + request.getParameterMap().keySet()
            );
        }
        cartService.addToCart(sessionId, productId, quantity);
        
        return "redirect:/products";
    }

    @PostMapping("/update")
    // enforce ownership before updating quantities
    public String updateCart(@RequestParam Long cartItemId,
                            @RequestParam Integer quantity,
                            HttpSession session,
                            HttpServletRequest request) {
        String sessionId = session.getId();
        CartItem item = cartService.getCartItemById(cartItemId);
        if (item == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Cart item not found");
        }
        if (!sessionId.equals(item.getSessionId())) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication != null ? authentication.getName() : "anonymous";
            securityEventService.logHighSeverityEvent(
                "ACCESS_CONTROL_VIOLATION",
                username,
                "Cart update blocked for non-owner session",
                "cartItemId=" + cartItemId + " | path=" + request.getRequestURI()
            );
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Forbidden");
        }
        if (quantity == null || quantity <= 0) {
            securityEventService.logHighSeverityEvent(
                "AMOUNT_TAMPERING",
                "anonymous",
                "Invalid cart quantity update",
                "quantity=" + quantity
            );
        }
        cartService.updateQuantity(sessionId, cartItemId, quantity);
        return "redirect:/cart";
    }

    @PostMapping("/remove")
    // remove a single item from the cart
    public String removeFromCart(@RequestParam Long cartItemId,
                                HttpSession session) {
        String sessionId = session.getId();
        cartService.removeFromCart(sessionId, cartItemId);
        return "redirect:/cart";
    }

    @PostMapping("/clear")
    // clear the session cart
    public String clearCart(HttpSession session) {
        String sessionId = session.getId();
        cartService.clearCart(sessionId);
        return "redirect:/cart";
    }

}
