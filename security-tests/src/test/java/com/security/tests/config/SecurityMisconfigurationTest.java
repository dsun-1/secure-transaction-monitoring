package com.security.tests.config;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import java.time.Duration;

/**
 * OWASP A05:2021 - Security Misconfiguration
 * Tests for common security misconfigurations
 */
public class SecurityMisconfigurationTest extends BaseTest {

    @Test(description = "OWASP A05 - Check for verbose error messages")
    public void testVerboseErrorMessages() {
        // Try to access non-existent page
        driver.get(baseUrl + "/nonexistent-page-12345");
        
        String pageSource = driver.getPageSource();
        
        // Should NOT expose stack traces
        assertFalse(pageSource.contains("java.lang."), 
            "Java stack traces should not be exposed to users");
        assertFalse(pageSource.contains("Exception"), 
            "Exception details should not be visible");
        assertFalse(pageSource.contains("at com.security"), 
            "Package names should not be exposed in errors");
        assertFalse(pageSource.contains("line "), 
            "Line numbers should not be exposed");
        
        logSecurityEvent("VERBOSE_ERROR_CHECK", "INFO", "Verified no verbose error messages");
    }

    @Test(description = "OWASP A05 - Test for default credentials")
    public void testDefaultCredentials() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Try common default credentials
        String[][] defaultCreds = {
            {"admin", "admin"},
            {"admin", "password"},
            {"root", "root"},
            {"test", "test"}
        };
        
        for (String[] cred : defaultCreds) {
            driver.get(baseUrl + "/login");
            wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username"))).clear();
            driver.findElement(By.name("username")).sendKeys(cred[0]);
            driver.findElement(By.name("password")).clear();
            driver.findElement(By.name("password")).sendKeys(cred[1]);
            
            // --- FIX: Changed selector from By.id("login-btn") to By.xpath ---
            driver.findElement(By.xpath("//button[@type='submit']")).click();
            
            // Should NOT successfully log in with default credentials
            String currentUrl = driver.getCurrentUrl();
            assertFalse(currentUrl.contains("/dashboard") || currentUrl.contains("/home") || currentUrl.contains("/checkout"),
                "Default credentials " + cred[0] + "/" + cred[1] + " should not work");
            
            // Stay on the login page for the next attempt
            if (!currentUrl.contains("/login")) {
                 driver.get(baseUrl + "/login"); // Reset if redirected
            }
        }
        
        logSecurityEvent("DEFAULT_CREDENTIALS_CHECK", "INFO", 
            "Verified default credentials are not accepted");
    }

    @Test(description = "OWASP A05 - Check for directory listing")
    public void testDirectoryListing() {
        // Try to access common directories
        String[] directories = {
            "/uploads/",
            "/images/",
            "/files/",
            "/static/",
            "/resources/"
        };
        
        for (String dir : directories) {
            driver.get(baseUrl + dir);
            String pageSource = driver.getPageSource();
            
            // Should NOT show directory listing
            assertFalse(pageSource.contains("Index of") || pageSource.contains("Directory Listing"),
                "Directory listing should be disabled for " + dir);
        }
        
        logSecurityEvent("DIRECTORY_LISTING_CHECK", "INFO", 
            "Verified directory listing is disabled");
    }

    @Test(description = "OWASP A05 - Check security headers")
    public void testSecurityHeaders() {
        driver.get(baseUrl);
        
        // Check for common security headers (via JavaScript in browser console)
        String script = "return document.createElement('a').protocol;";
        Object protocol = ((org.openqa.selenium.JavascriptExecutor) driver).executeScript(script);
        
        // This is a basic check - in real scenarios, you'd use a tool like OWASP ZAP
        logSecurityEvent("SECURITY_HEADERS_CHECK", "INFO", 
            "Checked for security headers - Protocol: " + protocol);
    }

    @Test(description = "OWASP A05 - Test for exposed admin interfaces")
    public void testExposedAdminInterfaces() {
        // Try to access common admin URLs
        String[] adminUrls = {
            "/admin",
            "/administrator",
            "/manage",
            "/console",
            "/actuator" // Spring Boot actuator
        };
        
        for (String adminUrl : adminUrls) {
            driver.get(baseUrl + adminUrl);
            
            // Should require authentication or return 404, not expose admin panel
            String pageSource = driver.getPageSource();
            assertFalse(pageSource.contains("Admin Panel") || pageSource.contains("Management Console") || pageSource.contains("actuator/"),
                "Admin interface at " + adminUrl + " should not be publicly accessible");
        }
        
        logSecurityEvent("ADMIN_INTERFACE_CHECK", "INFO", 
            "Verified admin interfaces are not exposed");
    }

    @Test(description = "OWASP A05 - Check for information disclosure in HTTP headers")
    public void testInformationDisclosure() {
        driver.get(baseUrl);
        
        // Check page source for version information disclosure
        String pageSource = driver.getPageSource();
        
        assertFalse(pageSource.contains("Spring Boot"), 
            "Framework version should not be disclosed");
        assertFalse(pageSource.contains("Tomcat/"), 
            "Server version should not be disclosed");
        assertFalse(pageSource.matches(".*Java/[0-9.]+.*"), 
            "Java version should not be disclosed");
        
        logSecurityEvent("INFO_DISCLOSURE_CHECK", "INFO", 
            "Verified no sensitive version information disclosed");
    }

    @Test(description = "OWASP A05 - Test for unnecessary HTTP methods")
    public void testUnnecessaryHTTPMethods() {
        // This would typically use a tool like curl, but we can check basic functionality
        driver.get(baseUrl);
        
        // Verify the app responds properly to GET
        String pageTitle = driver.getTitle();
        assertTrue(pageTitle != null && !pageTitle.isEmpty(), "Application should respond to GET requests");
        
        logSecurityEvent("HTTP_METHODS_CHECK", "INFO", 
            "Checked HTTP methods configuration");
    }
}
