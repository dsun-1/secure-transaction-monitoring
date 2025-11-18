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
        int attemptCount = 10; // More than the 5-attempt lockout threshold
        
        // 1. Simulate failed login attempts to trigger the account lockout
        for (int i = 1; i <= attemptCount; i++) {
            WebElement usernameField = driver.findElement(By.id("username"));
            WebElement passwordField = driver.findElement(By.id("password"));
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            
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
        
        // --- FIX START: Replace faulty page content check with functional security check ---

        // 2. Attempt a final login with the correct credentials (admin/admin123)
        navigateToUrl("/login");
        WebElement usernameField = driver.findElement(By.id("username"));
        WebElement passwordField = driver.findElement(By.id("password"));
        WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
        
        usernameField.clear();
        usernameField.sendKeys(testUsername);
        passwordField.clear();
        passwordField.sendKeys("admin123"); // The correct password for 'admin'
        loginButton.click();
        
        // 3. Assertion: Verify the login FAILED (i.e., we are still on the login page)
        String currentUrl = driver.getCurrentUrl();
        Assert.assertTrue(currentUrl.contains("/login") || currentUrl.contains("?error"),
            "Brute force protection failed: Locked account was able to successfully log in.");
        
        // Log security event for successful *prevention*
        logSecurityEvent("BRUTE_FORCE_PREVENTION_SUCCESS", "HIGH", 
            "Account lockout successfully prevented correct login after " + attemptCount + " failed attempts for user: " + testUsername);
        
        // --- FIX END ---
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
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            
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
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            
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