package com.security.ecommerce.service;

import com.security.ecommerce.model.CartItem;
import com.security.ecommerce.model.Product;
import com.security.ecommerce.repository.CartItemRepository;
import com.security.ecommerce.repository.ProductRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.util.List;

@Service
@Transactional
public class CartService {

    private final CartItemRepository cartItemRepository;
    private final ProductRepository productRepository;

    public CartService(CartItemRepository cartItemRepository,
                       ProductRepository productRepository) {
        this.cartItemRepository = cartItemRepository;
        this.productRepository = productRepository;
    }

    public List<CartItem> getCartItems(String sessionId) {
        return cartItemRepository.findBySessionId(sessionId);
    }

    public CartItem getCartItemById(Long cartItemId) {
        if (cartItemId == null) {
            return null;
        }
        return cartItemRepository.findById(cartItemId).orElse(null);
    }

    public CartItem addToCart(String sessionId, Long productId, Integer quantity) {
        if (productId == null || quantity == null || quantity <= 0) {
            return null;
        }

        Product product = productRepository.findById(productId).orElse(null);
        
        if (product == null) {
            return null;
        }

        
        List<CartItem> cartItems = cartItemRepository.findBySessionId(sessionId);
        for (CartItem item : cartItems) {
            if (item.getProduct().getId().equals(productId)) {
                int newQuantity = item.getQuantity() + quantity;
                if (newQuantity <= 0) {
                    cartItemRepository.delete(item);
                    return null;
                }
                item.setQuantity(newQuantity);
                return cartItemRepository.save(item);
            }
        }

        
        CartItem cartItem = new CartItem();
        cartItem.setSessionId(sessionId);
        cartItem.setProduct(product);
        cartItem.setQuantity(quantity);
        cartItem.setPrice(product.getPrice());
        
        return cartItemRepository.save(cartItem);
    }

    public void updateQuantity(String sessionId, Long cartItemId, Integer quantity) {
        if (cartItemId == null || quantity == null) {
            return;
        }

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
        if (cartItemId == null) {
            return;
        }

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
}
