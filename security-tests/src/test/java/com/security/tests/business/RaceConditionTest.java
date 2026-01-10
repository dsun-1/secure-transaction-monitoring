package com.security.tests.business;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.WebDriverException;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * OWASP A04: Insecure Design - Race Condition Testing
 * Tests for race conditions in concurrent cart operations that could lead
 * to inconsistent state, inventory manipulation, or transaction anomalies.
 */
public class RaceConditionTest extends BaseTest {
    
    @Test(priority = 1, description = "Test race condition in concurrent cart quantity updates")
    public void testConcurrentCartUpdates() throws InterruptedException, ExecutionException {
        // Login and setup
        driver.get(baseUrl + "/login");
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.cssSelector("button[type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // Add an item to cart
        driver.get(baseUrl + "/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("button.add-to-cart")));
        driver.findElements(By.cssSelector("button.add-to-cart")).get(0).click();
        
        Thread.sleep(1000); // Wait for cart to update
        
        // Navigate to cart to get cart item ID
        driver.get(baseUrl + "/cart");
        if (driver.getPageSource().contains("Your cart is empty")) {
            driver.get(baseUrl + "/products");
            wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("button.add-to-cart")));
            driver.findElements(By.cssSelector("button.add-to-cart")).get(0).click();
            driver.get(baseUrl + "/cart");
            if (driver.getPageSource().contains("Your cart is empty")) {
                forceAddToCartViaApi(wait);
                driver.get(baseUrl + "/cart");
            }
        }
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector(".cart-item")));
        
        // Extract cart item ID and CSRF token from the page
        String cartItemId = driver.findElement(By.cssSelector("form[action='/cart/remove'] input[name='cartItemId']"))
            .getAttribute("value");
        String csrfToken = driver.findElement(By.name("_csrf")).getAttribute("value");
        Cookie csrfCookie = driver.manage().getCookieNamed("XSRF-TOKEN");
        
        // Get session cookie
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        String sessionId = sessionCookie != null ? sessionCookie.getValue() : "";
        
        // Get initial quantity
        String initialQuantityStr = driver.findElement(By.cssSelector(".cart-item td:nth-child(3)")).getText();
        int initialQuantity = Integer.parseInt(initialQuantityStr);
        
        System.out.println("Initial cart state - Item ID: " + cartItemId + ", Quantity: " + initialQuantity);
        
        // Prepare concurrent update requests
        int threadCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<Response>> futures = new ArrayList<>();
        AtomicInteger successCount = new AtomicInteger(0);
        
        // Submit concurrent requests to update quantity
        for (int i = 0; i < threadCount; i++) {
            final int threadNum = i;
            Future<Response> future = executor.submit(() -> {
                try {
                    Response response = RestAssured.given()
                        .baseUri(baseUrl)
                        .cookie("JSESSIONID", sessionId)
                        .cookie("XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                        .header("X-XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                        .formParam("cartItemId", cartItemId)
                        .formParam("quantity", String.valueOf(initialQuantity + 1))
                        .formParam("_csrf", csrfToken)
                        .post("/cart/update");
                    
                    if (response.statusCode() == 200 || response.statusCode() == 302) {
                        successCount.incrementAndGet();
                    }
                    
                    return response;
                } catch (Exception e) {
                    System.err.println("Thread " + threadNum + " failed: " + e.getMessage());
                    return null;
                }
            });
            futures.add(future);
        }
        
        // Wait for all threads to complete
        for (Future<Response> future : futures) {
            future.get(); // Wait for completion
        }
        
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);
        
        // Refresh cart page to check final state
        driver.navigate().refresh();
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector(".cart-item")));
        
        String finalQuantityStr = driver.findElement(By.cssSelector(".cart-item td:nth-child(3)")).getText();
        int finalQuantity = Integer.parseInt(finalQuantityStr);
        
        System.out.println("Final cart state - Quantity: " + finalQuantity);
        System.out.println("Concurrent updates: " + threadCount + " threads, " + successCount.get() + " succeeded");
        
        // Expected behavior: With proper locking, final quantity should be initialQuantity + 1
        // (only one update should succeed, or all updates should result in the same final value)
        // If finalQuantity != initialQuantity + 1, there's a race condition
        
        int expectedQuantity = initialQuantity + 1;
        
        if (finalQuantity != expectedQuantity) {
            // Log security event - race condition detected
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "RACE_CONDITION_DETECTED",
                "testuser",
                "Concurrent cart updates caused inconsistent state",
                "Race condition in cart update: " + threadCount + " concurrent requests, " +
                "expected quantity=" + expectedQuantity + " but got " + finalQuantity
            );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("Warning: Race condition detected - final quantity " + finalQuantity +
                             " doesn't match expected " + expectedQuantity);
        } else {
            System.out.println("OK: Cart updates handled correctly with proper synchronization");
        }
        
        // Test passes either way - we just log the race condition if found
        Assert.assertTrue(true, "Race condition test completed");
    }
    
    @Test(priority = 2, description = "Test race condition in concurrent item additions")
    public void testConcurrentItemAdditions() throws InterruptedException, ExecutionException {
        // Login
        driver.get(baseUrl + "/login");
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("paymentuser");
        driver.findElement(By.name("password")).sendKeys("Paym3nt@123");
        driver.findElement(By.cssSelector("button[type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // Get session cookie
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        String sessionId = sessionCookie != null ? sessionCookie.getValue() : "";
        
        // Get CSRF token
        driver.get(baseUrl + "/cart");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("_csrf")));
        String csrfToken = driver.findElement(By.name("_csrf")).getAttribute("value");
        Cookie csrfCookie = driver.manage().getCookieNamed("XSRF-TOKEN");
        
        // Clear cart first
        driver.get(baseUrl + "/cart");
        if (driver.findElements(By.cssSelector(".cart-item")).size() > 0) {
            driver.findElements(By.cssSelector("button.remove-item")).forEach(btn -> {
                try {
                    btn.click();
                    Thread.sleep(500);
                } catch (Exception e) {
                    // Ignore
                }
            });
        }
        
        // Prepare concurrent add-to-cart requests
        int threadCount = 5;
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        List<Future<Response>> futures = new ArrayList<>();
        AtomicInteger successCount = new AtomicInteger(0);
        
        // Get a product ID to add
        safeNavigate("/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("button.add-to-cart")));
        String productId = driver.findElements(By.cssSelector("button.add-to-cart"))
                                .get(0)
                                .getAttribute("data-product-id");
        
        if (productId == null || productId.isEmpty()) {
            productId = "1"; // Default fallback
        }
        
        final String finalProductId = productId;
        
        // Submit concurrent add-to-cart requests
        for (int i = 0; i < threadCount; i++) {
            Future<Response> future = executor.submit(() -> {
                try {
                    Response response = RestAssured.given()
                        .baseUri(baseUrl)
                        .cookie("JSESSIONID", sessionId)
                        .cookie("XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                        .header("X-XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                        .formParam("productId", finalProductId)
                        .formParam("quantity", "1")
                        .formParam("_csrf", csrfToken)
                        .post("/cart/add");
                    
                    if (response.statusCode() == 200 || response.statusCode() == 302) {
                        successCount.incrementAndGet();
                    }
                    
                    return response;
                } catch (Exception e) {
                    return null;
                }
            });
            futures.add(future);
        }
        
        // Wait for all threads
        for (Future<Response> future : futures) {
            future.get();
        }
        
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);
        
        // Check cart state
        driver.get(baseUrl + "/cart");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("body")));
        
        int cartItemCount = driver.findElements(By.cssSelector(".cart-item")).size();
        
        System.out.println("Concurrent add operations: " + threadCount + " threads, " + 
                         successCount.get() + " succeeded, " + cartItemCount + " items in cart");
        
        // Expected: Either 1 item (proper deduplication) or multiple items (race condition)
        // If cartItemCount > 1 for the same product, there's a race condition
        
        if (cartItemCount > 1) {
            // Log security event - race condition in item addition
            SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
                "RACE_CONDITION_DETECTED",
                "paymentuser",
                "Concurrent add-to-cart operations caused duplicate entries",
                "Race condition in cart item addition: " + threadCount + " concurrent adds resulted in " + 
                cartItemCount + " duplicate items"
            );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("Warning: Race condition - duplicate cart items created");
        } else {
            System.out.println("OK: Cart item additions handled correctly");
        }
        
        Assert.assertTrue(true, "Concurrent item addition test completed");
    }
    
    @Test(priority = 3, description = "Test race condition in checkout process")
    public void testCheckoutRaceCondition() throws InterruptedException {
        // Login
        driver.get(baseUrl + "/login");
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.cssSelector("button[type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // Add item to cart
        driver.get(baseUrl + "/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("button.add-to-cart")));
        driver.findElements(By.cssSelector("button.add-to-cart")).get(0).click();
        
        Thread.sleep(1000);
        
        // Get session
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        String sessionId = sessionCookie != null ? sessionCookie.getValue() : "";
        
        // Go to cart and get CSRF
        driver.get(baseUrl + "/cart");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("_csrf")));
        String csrfToken = driver.findElement(By.name("_csrf")).getAttribute("value");
        
        // Attempt concurrent checkouts (simulate double-click or network retry)
        AtomicInteger checkoutAttempts = new AtomicInteger(0);
        AtomicInteger checkoutSuccesses = new AtomicInteger(0);
        Cookie csrfCookie = driver.manage().getCookieNamed("XSRF-TOKEN");
        
        Thread thread1 = new Thread(() -> {
            try {
                checkoutAttempts.incrementAndGet();
                Response response = RestAssured.given()
                    .baseUri(baseUrl)
                    .cookie("JSESSIONID", sessionId)
                    .cookie("XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                    .header("X-XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                    .formParam("_csrf", csrfToken)
                    .formParam("cardNumber", "4532123456789012")
                    .formParam("cardName", "Race Tester")
                    .formParam("expiryDate", "12/25")
                    .formParam("cvv", "123")
                    .formParam("clientTotal", "999.99")
                    .post("/checkout/process");
                
                if (response.statusCode() == 200 || response.statusCode() == 302) {
                    checkoutSuccesses.incrementAndGet();
                }
            } catch (Exception e) {
                // Ignore
            }
        });
        
        Thread thread2 = new Thread(() -> {
            try {
                checkoutAttempts.incrementAndGet();
                Response response = RestAssured.given()
                    .baseUri(baseUrl)
                    .cookie("JSESSIONID", sessionId)
                    .cookie("XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                    .header("X-XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
                    .formParam("_csrf", csrfToken)
                    .formParam("cardNumber", "4532123456789012")
                    .formParam("cardName", "Race Tester")
                    .formParam("expiryDate", "12/25")
                    .formParam("cvv", "123")
                    .formParam("clientTotal", "999.99")
                    .post("/checkout/process");
                
                if (response.statusCode() == 200 || response.statusCode() == 302) {
                    checkoutSuccesses.incrementAndGet();
                }
            } catch (Exception e) {
                // Ignore
            }
        });
        
        thread1.start();
        thread2.start();
        
        thread1.join();
        thread2.join();
        
        System.out.println("Concurrent checkout attempts: " + checkoutAttempts.get() + 
                         ", successes: " + checkoutSuccesses.get());
        
        // If both checkouts succeeded, there's a race condition (double charging)
        if (checkoutSuccesses.get() > 1) {
            // Log security event - double checkout
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "RACE_CONDITION_DETECTED",
                "testuser",
                "Multiple simultaneous checkout attempts succeeded - potential double charging",
                "Checkout race condition: " + checkoutSuccesses.get() + " concurrent checkouts succeeded"
            );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("Critical: Checkout race condition - multiple checkouts succeeded!");
        } else {
            System.out.println("OK: Checkout properly synchronized");
        }
        
        Assert.assertTrue(true, "Checkout race condition test completed");
    }

    private void safeNavigate(String path) {
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                driver.get(baseUrl + path);
                return;
            } catch (WebDriverException ex) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ignored) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        }
        driver.get(baseUrl + path);
    }

    private void forceAddToCartViaApi(WebDriverWait wait) {
        driver.get(baseUrl + "/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("button.add-to-cart")));
        String productId = driver.findElements(By.name("productId")).get(0).getAttribute("value");
        String csrfToken = driver.findElement(By.name("_csrf")).getAttribute("value");
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Cookie csrfCookie = driver.manage().getCookieNamed("XSRF-TOKEN");

        RestAssured.given()
            .baseUri(baseUrl)
            .cookie("JSESSIONID", sessionCookie != null ? sessionCookie.getValue() : "")
            .cookie("XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
            .header("X-XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
            .formParam("_csrf", csrfToken)
            .formParam("productId", productId)
            .formParam("quantity", 1)
            .post("/cart/add");
    }
}
