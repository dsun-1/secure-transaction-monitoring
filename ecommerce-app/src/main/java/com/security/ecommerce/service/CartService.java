package com.security.ecommerce.service;

import com.security.ecommerce.model.CartItem;
import com.security.ecommerce.model.Product;
import com.security.ecommerce.repository.CartItemRepository;
import com.security.ecommerce.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;

@Service
@Transactional
public class CartService {

    @Autowired
    private CartItemRepository cartItemRepository;

    @Autowired
    private ProductRepository productRepository;

    public List<CartItem> getCartItems(String sessionId) {
        return cartItemRepository.findBySessionId(sessionId);
    }

    public CartItem addToCart(String sessionId, Long productId, Integer quantity) {
        Product product = productRepository.findById(productId).orElse(null);
        
        if (product == null) {
            return null;
        }

        // Check if item already in cart
        List<CartItem> cartItems = cartItemRepository.findBySessionId(sessionId);
        for (CartItem item : cartItems) {
            if (item.getProduct().getId().equals(productId)) {
                item.setQuantity(item.getQuantity() + quantity);
                return cartItemRepository.save(item);
            }
        }

        // Add new item
        CartItem cartItem = new CartItem();
        cartItem.setSessionId(sessionId);
        cartItem.setProduct(product);
        cartItem.setQuantity(quantity);
        cartItem.setPrice(product.getPrice());
        
        return cartItemRepository.save(cartItem);
    }

    public void updateQuantity(String sessionId, Long cartItemId, Integer quantity) {
        CartItem item = cartItemRepository.findById(cartItemId).orElse(null);
        if (item != null && item.getSessionId().equals(sessionId)) {
            if (quantity <= 0) {
                cartItemRepository.delete(item);
            } else {
                item.setQuantity(quantity);
                cartItemRepository.save(item);
            }
        }
    }

    public void removeFromCart(String sessionId, Long cartItemId) {
        CartItem item = cartItemRepository.findById(cartItemId).orElse(null);
        if (item != null && item.getSessionId().equals(sessionId)) {
            cartItemRepository.delete(item);
        }
    }

    public void clearCart(String sessionId) {
        cartItemRepository.deleteBySessionId(sessionId);
    }

    public BigDecimal getCartTotal(String sessionId) {
        List<CartItem> items = cartItemRepository.findBySessionId(sessionId);
        return items.stream()
                .map(CartItem::getSubtotal)
                .reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    public int getCartItemCount(String sessionId) {
        List<CartItem> items = cartItemRepository.findBySessionId(sessionId);
        return items.stream()
                .mapToInt(CartItem::getQuantity)
                .sum();
    }
}
