package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Tests for brute force attack detection and prevention.
 * Simulates multiple failed login attempts to verify rate limiting and account lockout.
 */
public class BruteForceTest extends BaseTest {
    
    @Test(priority = 1, description = "Verify brute force protection with rapid login attempts")
    public void testBruteForceProtection() {
        navigateToUrl("/login");
        
        String testUsername = "admin";
        String wrongPassword = "wrongpassword";
        int attemptCount = 10;
        
        for (int i = 1; i <= attemptCount; i++) {
            WebElement usernameField = driver.findElement(By.id("username"));
            WebElement passwordField = driver.findElement(By.id("password"));
            WebElement loginButton = driver.findElement(By.id("loginButton"));
            
            usernameField.clear();
            usernameField.sendKeys(testUsername);
            passwordField.clear();
            passwordField.sendKeys(wrongPassword + i);
            loginButton.click();
            
            // Log each failed attempt
            eventLogger.logAuthenticationAttempt(
                testUsername, 
                false, 
                "127.0.0.1", 
                "Brute force attempt #" + i
            );
            
            try {
                Thread.sleep(500); // Small delay between attempts
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        
        // After multiple failures, account should be locked or CAPTCHA should appear
        boolean isProtected = driver.getPageSource().contains("Too many login attempts") ||
                             driver.getPageSource().contains("Account locked") ||
                             driver.findElements(By.className("captcha")).size() > 0;
        
        Assert.assertTrue(isProtected, 
            "System should implement brute force protection after " + attemptCount + " failed attempts");
        
        // Log security event
        logSecurityEvent("BRUTE_FORCE_DETECTED", "HIGH", 
            attemptCount + " rapid failed login attempts detected from same IP for user: " + testUsername);
    }
    
    @Test(priority = 2, description = "Test distributed brute force across multiple sessions")
    public void testDistributedBruteForce() {
        String testUsername = "user@example.com";
        int totalAttempts = 15;
        
        for (int i = 1; i <= totalAttempts; i++) {
            driver.manage().deleteAllCookies(); // Simulate new session
            navigateToUrl("/login");
            
            WebElement usernameField = driver.findElement(By.id("username"));
            WebElement passwordField = driver.findElement(By.id("password"));
            WebElement loginButton = driver.findElement(By.id("loginButton"));
            
            usernameField.sendKeys(testUsername);
            passwordField.sendKeys("attempt" + i);
            loginButton.click();
            
            eventLogger.logAuthenticationAttempt(
                testUsername, 
                false, 
                "127.0.0." + (i % 255), // Simulate different IPs
                "Distributed brute force attempt"
            );
        }
        
        // Log sophisticated attack pattern
        logSecurityEvent("DISTRIBUTED_BRUTE_FORCE", "HIGH", 
            "Coordinated brute force attack - Multiple failed attempts across different sessions/IPs detected for user: " + testUsername);
    }
    
    @Test(priority = 3, description = "Test credential stuffing with leaked credentials")
    public void testCredentialStuffing() {
        // Simulate credential stuffing with common leaked username/password combinations
        String[][] leakedCredentials = {
            {"admin", "admin123"},
            {"user@test.com", "password123"},
            {"testuser", "Test@1234"},
            {"john.doe", "Summer2023!"}
        };
        
        for (String[] credential : leakedCredentials) {
            driver.manage().deleteAllCookies();
            navigateToUrl("/login");
            
            WebElement usernameField = driver.findElement(By.id("username"));
            WebElement passwordField = driver.findElement(By.id("password"));
            WebElement loginButton = driver.findElement(By.id("loginButton"));
            
            usernameField.sendKeys(credential[0]);
            passwordField.sendKeys(credential[1]);
            loginButton.click();
            
            eventLogger.logAuthenticationAttempt(
                credential[0], 
                false, 
                "192.168.1.100", 
                "Credential stuffing attempt"
            );
        }
        
        logSecurityEvent("CREDENTIAL_STUFFING", "HIGH",
            "Automated login attempts with leaked credential database detected");
    }
}
