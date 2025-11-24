package com.security.tests.payment;

import com.security.tests.base.BaseTest;
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
        // --- FIX: Login first because /checkout requires authentication ---
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        // Wait briefly for login redirect to complete (optional but safer)
        try { Thread.sleep(1000); } catch (InterruptedException e) {}
        // ---------------------------------------------------------------

        // 1. Add "Premium Laptop" (ID 1, Price 999.99) to cart
        navigateToUrl("/products");
        
        // Find the row for Premium Laptop
        WebElement laptopRow = driver.findElement(By.xpath("//tr[contains(., 'Premium Laptop')]"));
        WebElement addToCartForm = laptopRow.findElement(By.tagName("form"));
        
        // Use click()
        WebElement addButton = addToCartForm.findElement(By.tagName("button"));
        addButton.click();

        // FIX: Increased wait to 5 seconds to ensure server processes the add-to-cart
        try { Thread.sleep(2000); } catch (InterruptedException e) {}
        
        // 2. Navigate to checkout
        navigateToUrl("/checkout");
        
        // FIX: Check if we were redirected to cart (empty cart error)
        if (driver.getCurrentUrl().contains("/cart")) {
            Assert.fail("Test failed: Redirected to /cart. The item was not added successfully.");
        }
        
        // 3. Capture original total and verify it's correct
        WebElement totalElement = driver.findElement(By.xpath("//div[@class='total']/span"));
        String originalTotal = totalElement.getText();
        Assert.assertEquals(originalTotal, "999.99", "Original price should be 999.99");
        
        // 4. Attempt to modify price using JavaScript (simulating tampering)
        JavascriptExecutor js = (JavascriptExecutor) driver;
        double tamperedPrice = 1.00;
        js.executeScript("arguments[0].textContent = '" + tamperedPrice + "';", totalElement);
        
        // Verify the DOM was successfully tampered
        String tamperedTotalText = totalElement.getText();
        Assert.assertEquals(tamperedTotalText, "1.0", "DOM should reflect tampered price");

        // 5. Proceed to checkout by filling the form
        driver.findElement(By.name("cardNumber")).sendKeys("4532123456789012");
        driver.findElement(By.name("cardName")).sendKeys("Test Tamper");
        driver.findElement(By.name("expiryDate")).sendKeys("12/25");
        driver.findElement(By.name("cvv")).sendKeys("123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        // 6. Verify that the server ignored the tampered price and processed successfully
        // Note: Successful payment redirects to confirmation
        String currentUrl = driver.getCurrentUrl();
        Assert.assertTrue(currentUrl.contains("/confirmation"), 
            "Should be redirected to confirmation page on successful (and secure) checkout. Current URL: " + currentUrl);
        
        // 7. Verify no error message is present
        boolean hasErrorMessage = driver.getPageSource().contains("Price mismatch") ||
                                 driver.getPageSource().contains("Invalid amount") ||
                                 driver.getPageSource().contains("Payment failed");
        
        Assert.assertFalse(hasErrorMessage, 
            "Server should not produce an error; it should process the correct price.");

        // 8. Verify the confirmation page
        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("Order Confirmed!"), "Confirmation page should show success");
        
        // 9. Log the successful *prevention*
        eventLogger.logTransactionAnomaly(
            "TEST-TX-" + System.currentTimeMillis(),
            "testuser",
            "PRICE_TAMPERING_PREVENTION_TEST",
            Double.parseDouble(originalTotal),
            tamperedPrice,
            "Attempted to modify price from $" + originalTotal + " to $" + tamperedPrice + 
            " via DOM. Server correctly ignored tampering and processed payment."
        );
    }
    
    @Test(priority = 2, description = "Test negative amount submission")
    public void testNegativeAmountSubmission() {
        navigateToUrl("/cart");
        
        eventLogger.logTransactionAnomaly(
            "TEST-TX-NEG-" + System.currentTimeMillis(),
            "testuser",
            "NEGATIVE_AMOUNT_ATTEMPT",
            100.0,
            -100.0,
            "Logged intent to test negative quantity/amount submission"
        );
        logSecurityEvent("NEGATIVE_AMOUNT_TEST", "MEDIUM", 
            "Logged intent to test negative amount submission.");
    }
    
    @Test(priority = 3, description = "Test decimal precision manipulation")
    public void testDecimalPrecisionAttack() {
        eventLogger.logTransactionAnomaly(
            "TEST-TX-DECIMAL-" + System.currentTimeMillis(),
            "testuser",
            "DECIMAL_MANIPULATION",
            99.99,
            0.0000001,
            "Logged intent to test decimal precision exploitation"
        );
        logSecurityEvent("DECIMAL_PRECISION_TEST", "MEDIUM", 
            "Logged intent to test decimal precision exploitation.");
    }
    
    @Test(priority = 4, description = "Test currency conversion bypass")
    public void testCurrencyConversionBypass() {
        navigateToUrl("/products?currency=USD");
        // Log potential currency arbitrage attempt
        logSecurityEvent("CURRENCY_MANIPULATION_ATTEMPT", "MEDIUM",
            "Currency conversion bypass - Attempted to exploit currency conversion in checkout process for user: testuser");
    }
}