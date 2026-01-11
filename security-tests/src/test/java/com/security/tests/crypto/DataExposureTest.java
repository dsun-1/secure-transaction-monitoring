package com.security.tests.crypto;

import com.security.tests.base.BaseTest;
import com.security.tests.utils.SecurityEvent;
import org.openqa.selenium.By;
import org.openqa.selenium.JavascriptExecutor;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;
import java.util.Set;

/**
 * OWASP A02: Cryptographic Failures - Sensitive Data Exposure Testing
 * Tests for sensitive data leakage in client-side storage (localStorage, sessionStorage)
 * and verifies proper cookie security flags (HttpOnly, Secure).
 */
public class DataExposureTest extends BaseTest {
    
    @Test(priority = 1, description = "Check localStorage for sensitive data exposure")
    public void testLocalStorageSensitiveData() {
        // Login first to ensure session is established
        driver.get(baseUrl + "/login");
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.cssSelector("button[type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // Execute JavaScript to check localStorage
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String localStorageData = (String) js.executeScript(
            "return JSON.stringify(localStorage);"
        );
        
        // Check for sensitive keywords
        String[] sensitiveKeywords = {
            "password", "passwd", "pwd",
            "secret", "token", "apikey", "api_key",
            "creditcard", "credit_card", "ssn",
            "private_key", "privatekey"
        };
        
        boolean foundSensitiveData = false;
        String foundKeyword = null;
        
        for (String keyword : sensitiveKeywords) {
            if (localStorageData.toLowerCase().contains(keyword)) {
                foundSensitiveData = true;
                foundKeyword = keyword;
                break;
            }
        }
        
        if (foundSensitiveData) {
            // Log security event - sensitive data in localStorage
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "CRYPTOGRAPHIC_FAILURE",
                "testuser",
                "Client-side storage contains potentially sensitive information",
                "Sensitive data ('" + foundKeyword + "') found in localStorage"
            );
            eventLogger.logSecurityEvent(event);
            
            Assert.fail("Sensitive data ('" + foundKeyword + "') found in localStorage. " +
                       "localStorage should not contain passwords, tokens, or other secrets.");
        }
        
        System.out.println("✓ No sensitive data found in localStorage");
    }
    
    @Test(priority = 2, description = "Check sessionStorage for sensitive data exposure")
    public void testSessionStorageSensitiveData() {
        // Reuse existing session from previous test or login again
        if (!driver.getCurrentUrl().contains("/products")) {
            driver.get(baseUrl + "/login");
            WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
            
            wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
            driver.findElement(By.name("username")).sendKeys("testuser");
            driver.findElement(By.name("password")).sendKeys("password123");
            driver.findElement(By.cssSelector("button[type='submit']")).click();
            
            wait.until(ExpectedConditions.urlContains("/products"));
        }
        
        // Execute JavaScript to check sessionStorage
        JavascriptExecutor js = (JavascriptExecutor) driver;
        String sessionStorageData = (String) js.executeScript(
            "return JSON.stringify(sessionStorage);"
        );
        
        // Check for sensitive keywords
        String[] sensitiveKeywords = {
            "password", "passwd", "pwd",
            "secret", "token", "apikey", "api_key",
            "creditcard", "credit_card", "ssn"
        };
        
        boolean foundSensitiveData = false;
        String foundKeyword = null;
        
        for (String keyword : sensitiveKeywords) {
            if (sessionStorageData.toLowerCase().contains(keyword)) {
                foundSensitiveData = true;
                foundKeyword = keyword;
                break;
            }
        }
        
        if (foundSensitiveData) {
            // Log security event - sensitive data in sessionStorage
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "CRYPTOGRAPHIC_FAILURE",
                "testuser",
                "Client-side storage contains potentially sensitive information",
                "Sensitive data ('" + foundKeyword + "') found in sessionStorage"
            );
            eventLogger.logSecurityEvent(event);
            
            Assert.fail("Sensitive data ('" + foundKeyword + "') found in sessionStorage. " +
                       "sessionStorage should not contain passwords, tokens, or other secrets.");
        }
        
        System.out.println("✓ No sensitive data found in sessionStorage");
    }
    
    @Test(priority = 3, description = "Verify session cookies have HttpOnly flag")
    public void testHttpOnlyCookieFlag() {
        // Login to get session cookies
        driver.get(baseUrl + "/login");
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.cssSelector("button[type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // Check cookies for HttpOnly flag
        Set<org.openqa.selenium.Cookie> cookies = driver.manage().getCookies();
        
        boolean foundSessionCookie = false;
        boolean allSessionCookiesSecure = true;
        String insecureCookieName = null;
        
        for (org.openqa.selenium.Cookie cookie : cookies) {
            String cookieName = cookie.getName().toLowerCase();
            
            // Check if this is a session-related cookie
            if (cookieName.contains("session") || cookieName.contains("jsessionid") || 
                cookieName.equals("xsrf-token") || cookieName.equals("csrf-token")) {
                
                foundSessionCookie = true;
                
                // Note: Selenium WebDriver cannot directly check HttpOnly flag
                // because HttpOnly cookies are not accessible to JavaScript
                // We'll check if cookie is accessible via JavaScript (it shouldn't be)
                JavascriptExecutor js = (JavascriptExecutor) driver;
                String jsAccessibleCookies = (String) js.executeScript("return document.cookie;");
                
                if (jsAccessibleCookies.contains(cookie.getName())) {
                    allSessionCookiesSecure = false;
                    insecureCookieName = cookie.getName();
                    break;
                }
            }
        }
        
        if (foundSessionCookie && !allSessionCookiesSecure) {
            // Log security event - session cookie accessible via JavaScript
            SecurityEvent event = SecurityEvent.createHighSeverityEvent(
                "CRYPTOGRAPHIC_FAILURE",
                "testuser",
                "XSS attacks can steal session cookies",
                "Session cookie '" + insecureCookieName + "' accessible via JavaScript (missing HttpOnly flag)"
            );
            eventLogger.logSecurityEvent(event);
            
            Assert.fail("Session cookie '" + insecureCookieName + "' is accessible via JavaScript. " +
                       "Session cookies should have HttpOnly flag to prevent XSS-based theft.");
        }
        
        System.out.println("✓ Session cookies properly protected with HttpOnly flag");
    }
    
    @Test(priority = 4, description = "Verify no passwords in page source or DOM")
    public void testPasswordExposureInDOM() {
        // Login page check
        driver.get(baseUrl + "/login");
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        wait.until(ExpectedConditions.presenceOfElementLocated(By.name("username")));
        
        // Check if password field has autocomplete enabled (should be off for security)
        WebElement passwordField = driver.findElement(By.name("password"));
        String autocomplete = passwordField.getDomProperty("autocomplete");
        
        // Password fields should have autocomplete="off" for security
        if (autocomplete != null && !autocomplete.equals("off") && !autocomplete.equals("current-password")) {
            System.out.println("Warning: Password field autocomplete is: " + autocomplete);
        }
        
        // Get page source to check for hardcoded credentials
        String pageSource = driver.getPageSource().toLowerCase();
        
        // Check for suspicious patterns in page source
        String[] suspiciousPatterns = {
            "password=\"", "password='", "pwd=\"", "pwd='",
            "default_password", "admin_password",
            "test_password=\"", "demo_password=\""
        };
        
        boolean foundSuspiciousPattern = false;
        String foundPattern = null;
        
        for (String pattern : suspiciousPatterns) {
            if (pageSource.contains(pattern.toLowerCase())) {
                foundSuspiciousPattern = true;
                foundPattern = pattern;
                break;
            }
        }
        
        if (foundSuspiciousPattern) {
            // Log security event - hardcoded credentials in source
            SecurityEvent event = SecurityEvent.createMediumSeverityEvent(
                "CRYPTOGRAPHIC_FAILURE",
                "anonymous",
                "Potential hardcoded credentials or password hints in client-side code",
                "Suspicious pattern '" + foundPattern + "' found in page source"
            );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("⚠ Warning: Suspicious pattern '" + foundPattern + "' found in page source");
        } else {
            System.out.println("✓ No hardcoded passwords or suspicious patterns in page source");
        }
    }
}
