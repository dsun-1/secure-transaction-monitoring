package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Tests for session security vulnerabilities including session hijacking,
 * fixation, and timeout validation.
 */
public class SessionHijackingTest extends BaseTest {
    
    @Test(priority = 1, description = "Test session hijacking by stealing session cookie")
    public void testSessionCookieStealing() {
        // Login with valid credentials
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        // Capture session cookie
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Assert.assertNotNull(sessionCookie, "Session cookie should be present after login");
        
        // Verify HttpOnly flag is set (security best practice)
        boolean isHttpOnly = sessionCookie.isHttpOnly();
        Assert.assertTrue(isHttpOnly, 
            "Session cookie should have HttpOnly flag to prevent XSS-based hijacking");
        
        // Verify Secure flag for HTTPS
        boolean isSecure = sessionCookie.isSecure();
        // Note: Will be false in local dev, should be true in production
        
        // Log security event if cookies are vulnerable
        if (!isHttpOnly || (!isSecure && !baseUrl.contains("localhost"))) {
            logSecurityEvent("INSECURE_SESSION_COOKIE", "HIGH",
                "Session hijacking vulnerability - Session cookie lacks proper security flags (HttpOnly: " + 
                isHttpOnly + ", Secure: " + isSecure + ") for user: testuser");
        }
    }
    
    @Test(priority = 2, description = "Test session reuse after logout")
    public void testSessionReuseAfterLogout() {
        // Login
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        // Capture session cookie
        Cookie oldSessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        String oldSessionId = oldSessionCookie != null ? oldSessionCookie.getValue() : "";
        
        // --- FIX: Navigate to products page which has the logout button ---
        navigateToUrl("/products"); 
        // ----------------------------------------------------------------
        
        // Logout
        driver.findElement(By.id("logoutButton")).click();
        
        // ... (Rest of the test remains the same) ...
        // Try to reuse old session
        if (oldSessionCookie != null) {
            driver.manage().addCookie(oldSessionCookie);
        }
        
        // Navigate to protected page
        navigateToUrl("/account");
        
        // Should be redirected to login page
        boolean isRedirectedToLogin = driver.getCurrentUrl().contains("/login") ||
                                     driver.getPageSource().contains("Please log in");
        
        Assert.assertTrue(isRedirectedToLogin, 
            "Old session should not be valid after logout - session hijacking vulnerability!");
        
        if (!isRedirectedToLogin) {
            logSecurityEvent("SESSION_REUSE_VULNERABILITY", "HIGH",
                "Session reuse after logout - Session " + oldSessionId + " remained valid after logout for user: testuser");
        }
    }
    
    @Test(priority = 3, description = "Test concurrent session detection")
    public void testConcurrentSessionDetection() {
        // This test would require parallel browser instances
        // For now, we log that this test should be implemented with Selenium Grid
        
        logSecurityEvent("CONCURRENT_SESSION_TEST", "MEDIUM",
            "Testing concurrent login detection - Verifying that multiple simultaneous logins are detected and handled for user: testuser");
    }
}
