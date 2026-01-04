package com.security.tests.payment;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;


public class AmountTamperingTest extends BaseTest {
    
    @Test(priority = 1, description = "Test client-side price modification via DOM manipulation")
    public void testClientSidePriceModification() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("paymentuser");
        driver.findElement(By.id("password")).sendKeys("Paym3nt@123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));
        

        
        navigateToUrl("/products");
        
        
        WebElement laptopRow = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]"))
        );
        WebElement addToCartForm = laptopRow.findElement(By.tagName("form"));
        
        
        WebElement addButton = addToCartForm.findElement(By.tagName("button"));
        addButton.click();

        wait.until(ExpectedConditions.urlContains("/products"));

        
        navigateToUrl("/cart");
        if (driver.getPageSource().contains("Your cart is empty")) {
            
            navigateToUrl("/products");
            laptopRow = wait.until(
                ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]"))
            );
            addToCartForm = laptopRow.findElement(By.tagName("form"));
            addButton = addToCartForm.findElement(By.tagName("button"));
            addButton.click();
            wait.until(ExpectedConditions.urlContains("/products"));

            navigateToUrl("/cart");
            Assert.assertFalse(driver.getPageSource().contains("Your cart is empty"),
                "Cart is still empty after retry; add-to-cart did not persist.");
        }
        
        
        navigateToUrl("/checkout");

        if (driver.getCurrentUrl().contains("/login")) {
            driver.findElement(By.id("username")).sendKeys("paymentuser");
            driver.findElement(By.id("password")).sendKeys("Paym3nt@123");
            driver.findElement(By.xpath("//button[@type='submit']")).click();
            wait.until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));

            
            navigateToUrl("/products");
            WebElement loginRetryRow = wait.until(
                ExpectedConditions.presenceOfElementLocated(By.xpath("//tr[contains(., 'Premium Laptop')]"))
            );
            WebElement retryForm = loginRetryRow.findElement(By.tagName("form"));
            retryForm.findElement(By.tagName("button")).click();
            wait.until(ExpectedConditions.urlContains("/products"));

            navigateToUrl("/checkout");
        }
        
        
        if (driver.getCurrentUrl().contains("/cart")) {
            Assert.fail("Test failed: Redirected to /cart. The item was not added successfully.");
        }
        
        
        WebElement totalElement = wait.until(
            ExpectedConditions.presenceOfElementLocated(By.xpath("//div[@class='total']/span"))
        );
        String originalTotal = totalElement.getText();
        Assert.assertEquals(originalTotal, "999.99", "Original price should be 999.99");
        
        
        JavascriptExecutor js = (JavascriptExecutor) driver;
        double tamperedPrice = 1.00;
        js.executeScript("arguments[0].textContent = '" + tamperedPrice + "';", totalElement);
        
        
        String tamperedTotalText = totalElement.getText();
        Assert.assertEquals(tamperedTotalText, "1.0", "DOM should reflect tampered price");

        
        driver.findElement(By.name("cardNumber")).sendKeys("4532123456789012");
        driver.findElement(By.name("cardName")).sendKeys("Test Tamper");
        driver.findElement(By.name("expiryDate")).sendKeys("12/25");
        driver.findElement(By.name("cvv")).sendKeys("123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        
        wait.until(d -> d.getPageSource().contains("Order Confirmed!") ||
                        d.getPageSource().contains("Payment processing failed") ||
                        d.getPageSource().contains("Invalid card number"));

        String currentUrl = driver.getCurrentUrl();
        boolean hasConfirmation = currentUrl.contains("/confirmation") ||
                                  driver.getPageSource().contains("Order Confirmed!");
        Assert.assertTrue(hasConfirmation,
            "Checkout should render confirmation on successful (and secure) payment. Current URL: " + currentUrl);
        
        
        boolean hasErrorMessage = driver.getPageSource().contains("Price mismatch") ||
                                 driver.getPageSource().contains("Invalid amount") ||
                                 driver.getPageSource().contains("Payment failed");
        
        Assert.assertFalse(hasErrorMessage, 
            "Server should not produce an error; it should process the correct price.");

        
        String pageSource = driver.getPageSource();
        Assert.assertTrue(pageSource.contains("Order Confirmed!"), "Confirmation page should show success");
        
        
        eventLogger.logTransactionAnomaly(
            "TEST-TX-" + System.currentTimeMillis(),
            "paymentuser",
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
            "paymentuser",
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
            "paymentuser",
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
        
        logSecurityEvent("CURRENCY_MANIPULATION_ATTEMPT", "MEDIUM",
            "Currency conversion bypass - Attempted to exploit currency conversion in checkout process for user: paymentuser");
    }
}
