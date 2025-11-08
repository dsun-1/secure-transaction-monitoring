package com.security.tests.payment;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Tests for payment amount tampering and price modification vulnerabilities.
 * Critical for transaction integrity.
 */
public class AmountTamperingTest extends BaseTest {
    
    @Test(priority = 1, description = "Test client-side price modification via DOM manipulation")
    public void testClientSidePriceModification() {
        // Add item to cart
        navigateToUrl("/products");
        driver.findElement(By.className("add-to-cart")).click();
        
        // Navigate to cart
        navigateToUrl("/cart");
        
        // Capture original price
        WebElement priceElement = driver.findElement(By.className("item-price"));
        String originalPrice = priceElement.getText().replaceAll("[^0-9.]", "");
        double original = Double.parseDouble(originalPrice);
        
        // Attempt to modify price using JavaScript (simulating tampering)
        JavascriptExecutor js = (JavascriptExecutor) driver;
        double tamperedPrice = original * 0.01; // 99% discount
        js.executeScript("arguments[0].textContent = '$" + tamperedPrice + "';", priceElement);
        
        // Also try to modify hidden form fields
        try {
            WebElement priceInput = driver.findElement(By.name("price"));
            js.executeScript("arguments[0].value = '" + tamperedPrice + "';", priceInput);
        } catch (Exception e) {
            // Hidden field might not exist
        }
        
        // Proceed to checkout
        driver.findElement(By.id("checkoutButton")).click();
        
        // Fill payment details
        driver.findElement(By.id("cardNumber")).sendKeys("4532123456789012");
        driver.findElement(By.id("cvv")).sendKeys("123");
        driver.findElement(By.id("submitPayment")).click();
        
        // Verify that server-side validation caught the tampering
        boolean hasErrorMessage = driver.getPageSource().contains("Price mismatch") ||
                                 driver.getPageSource().contains("Invalid amount") ||
                                 driver.getPageSource().contains("Payment failed");
        
        Assert.assertTrue(hasErrorMessage, 
            "Server MUST validate price on backend - client-side tampering vulnerability!");
        
        // Log transaction anomaly
        eventLogger.logTransactionAnomaly(
            "TEST-TX-" + System.currentTimeMillis(),
            "testuser",
            "PRICE_TAMPERING",
            original,
            tamperedPrice,
            "Attempted to modify price from $" + original + " to $" + tamperedPrice + 
            " via DOM manipulation"
        );
        
        if (!hasErrorMessage) {
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "PRICE_TAMPERING_SUCCESSFUL",
                "testuser",
                "Payment amount manipulation",
                "Successfully modified transaction amount from $" + original + 
                " to $" + tamperedPrice + " - CRITICAL VULNERABILITY"
            );
            eventLogger.logSecurityEvent(event);
        }
    }
    
    @Test(priority = 2, description = "Test negative amount submission")
    public void testNegativeAmountSubmission() {
        navigateToUrl("/cart");
        
        // Try to inject negative quantity to create negative total
        JavascriptExecutor js = (JavascriptExecutor) driver;
        WebElement quantityField = driver.findElement(By.name("quantity"));
        js.executeScript("arguments[0].value = '-10';", quantityField);
        
        driver.findElement(By.id("updateCart")).click();
        driver.findElement(By.id("checkoutButton")).click();
        
        // System should reject negative amounts
        boolean isRejected = driver.getPageSource().contains("Invalid quantity") ||
                            driver.getPageSource().contains("must be positive");
        
        Assert.assertTrue(isRejected, "Negative amounts should be rejected");
        
        eventLogger.logTransactionAnomaly(
            "TEST-TX-NEG-" + System.currentTimeMillis(),
            "testuser",
            "NEGATIVE_AMOUNT_ATTEMPT",
            100.0,
            -100.0,
            "Attempted to submit negative quantity/amount"
        );
    }
    
    @Test(priority = 3, description = "Test decimal precision manipulation")
    public void testDecimalPrecisionAttack() {
        // Test if system properly handles floating point arithmetic
        navigateToUrl("/cart");
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        WebElement priceInput = driver.findElement(By.name("price"));
        
        // Try to exploit floating point rounding
        js.executeScript("arguments[0].value = '0.0000001';", priceInput);
        
        driver.findElement(By.id("checkoutButton")).click();
        
        // Log the attempt
        eventLogger.logTransactionAnomaly(
            "TEST-TX-DECIMAL-" + System.currentTimeMillis(),
            "testuser",
            "DECIMAL_MANIPULATION",
            99.99,
            0.0000001,
            "Attempted decimal precision exploitation"
        );
    }
    
    @Test(priority = 4, description = "Test currency conversion bypass")
    public void testCurrencyConversionBypass() {
        // Add item in USD
        navigateToUrl("/products?currency=USD");
        driver.findElement(By.className("add-to-cart")).click();
        
        // Try to checkout in different currency without proper conversion
        navigateToUrl("/checkout?currency=EUR");
        
        // Log potential currency arbitrage attempt
        SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
            "CURRENCY_MANIPULATION_ATTEMPT",
            "testuser",
            "Currency conversion bypass",
            "Attempted to exploit currency conversion in checkout process"
        );
        eventLogger.logSecurityEvent(event);
    }
}
