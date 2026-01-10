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
        navigateToUrl("/login");
        
        String testUsername = "lockoutuser";
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
            
            try {
                Thread.sleep(500); 
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
        
        

        
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
            "Brute force protection failed: authentication should remain blocked after repeated attempts.");
        
        
        assertSecurityEventLogged("BRUTE_FORCE_DETECTED");
        
    }
    
    @Test(priority = 2, description = "Test distributed brute force across multiple sessions")
    public void testDistributedBruteForce() {
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
            
        }
        
        
        assertSecurityEventLogged("DISTRIBUTED_BRUTE_FORCE");
    }
    
    @Test(priority = 3, description = "Test credential stuffing with leaked credentials")
    public void testCredentialStuffing() {
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
            
        }
        
        assertSecurityEventLogged("CREDENTIAL_STUFFING");
    }
}
