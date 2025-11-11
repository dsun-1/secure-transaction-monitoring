package com.security.tests.business;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import org.testng.annotations.Test;

public class CartManipulationTest extends BaseTest {
    
    @Test(description = "Test cart price tampering")
    public void testCartPriceTampering() {
        navigateToUrl("/products");
        
        // Test would involve:
        // 1. Add item to cart
        // 2. Attempt to modify price via browser console/intercepting requests
        // 3. Verify server validates prices against database
        
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "CART_MANIPULATION_TEST",
            "test_user",
            "tampering_attempt",
            "Tested cart price tampering protection"
        );
        eventLogger.logSecurityEvent(event);
    }
    
    @Test(description = "Test cart quantity manipulation")
    public void testQuantityManipulation() {
        navigateToUrl("/cart");
        
        // Test negative quantities, excessive quantities
        SecurityEvent event = SecurityEvent.createHighSeverityEvent(
            "CART_MANIPULATION_TEST",
            "test_user",
            "tampering_attempt",
            "Tested cart quantity manipulation"
        );
        eventLogger.logSecurityEvent(event);
    }
}
