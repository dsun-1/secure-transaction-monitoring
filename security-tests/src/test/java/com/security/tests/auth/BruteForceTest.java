package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;


public class BruteForceTest extends BaseTest {
    
    @Test(priority = 1, description = "Verify brute force protection with rapid login attempts")
    public void testBruteForceProtection() {
        // simulate rapid failed logins to verify lockout behavior
        navigateToUrl("/login");
        
        String testUsername = "admin";
        String wrongPassword = "wrongpassword";
        int attemptCount = 10; 
        
        
        for (int i = 1; i <= attemptCount; i++) {
            WebElement usernameField = driver.findElement(By.id("username"));
            WebElement passwordField = driver.findElement(By.id("password"));
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            
            usernameField.clear();
            usernameField.sendKeys(testUsername);
            passwordField.clear();
            passwordField.sendKeys(wrongPassword + i);
            loginButton.click();
            
            
            // record each attempt for siem correlation
            eventLogger.logAuthenticationAttempt(
                testUsername, 
                false, 
                "127.0.0.1", 
                "Brute force attempt #" + i
            );
            
            try {
                Thread.sleep(500); 
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        
        

        
        // attempt a valid login after repeated failures to validate lockout
        navigateToUrl("/login");
        WebElement usernameField = driver.findElement(By.id("username"));
        WebElement passwordField = driver.findElement(By.id("password"));
        WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
        
        usernameField.clear();
        usernameField.sendKeys(testUsername);
        passwordField.clear();
        passwordField.sendKeys("admin123"); 
        loginButton.click();
        
        
        String currentUrl = driver.getCurrentUrl();
        Assert.assertTrue(currentUrl.contains("/login") || currentUrl.contains("?error"),
            "Brute force protection failed: Locked account was able to successfully log in.");
        
        
        // emit high-severity event to show detection in the pipeline
        logSecurityEvent("BRUTE_FORCE_PREVENTION_SUCCESS", "HIGH", 
            "Account lockout successfully prevented correct login after " + attemptCount + " failed attempts for user: " + testUsername);
        
        
    }
    
    @Test(priority = 2, description = "Test distributed brute force across multiple sessions")
    public void testDistributedBruteForce() {
        // simulate multiple sessions/ip sources to mimic distributed attacks
        String testUsername = "user@example.com";
        int totalAttempts = 15;
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        for (int i = 1; i <= totalAttempts; i++) {
            driver.manage().deleteAllCookies(); 
            navigateToUrl("/login");
            
            WebElement usernameField;
            WebElement passwordField;
            try {
                usernameField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username")));
                passwordField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("password")));
            } catch (TimeoutException e) {
                navigateToUrl("/login");
                usernameField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("username")));
                passwordField = wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("password")));
            }
            WebElement loginButton = driver.findElement(By.xpath("//button[@type='submit']"));
            
            usernameField.sendKeys(testUsername);
            passwordField.sendKeys("attempt" + i);
            loginButton.click();
            
            eventLogger.logAuthenticationAttempt(
                testUsername, 
                false, 
                "127.0.0." + (i % 255), 
                "Distributed brute force attempt"
            );
        }
        
        
        // log aggregated signal for the siem report
        logSecurityEvent("DISTRIBUTED_BRUTE_FORCE", "HIGH", 
            "Coordinated brute force attack - Multiple failed attempts across different sessions/IPs detected for user: " + testUsername);
    }
    
    @Test(priority = 3, description = "Test credential stuffing with leaked credentials")
    public void testCredentialStuffing() {
        // try common leaked credentials to simulate credential stuffing
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
        
        // emit a high-severity event for SOC-style alerting
        logSecurityEvent("CREDENTIAL_STUFFING", "HIGH",
            "Automated login attempts with leaked credential database detected");
    }
}
