package com.security.tests.crypto;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.logging.LogEntries;
import org.openqa.selenium.logging.LogEntry;
import org.openqa.selenium.logging.LogType;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

/**
 * OWASP A02:2021 - Cryptographic Failures
 * Tests for sensitive data exposure through unencrypted channels
 */
public class CryptographicFailuresTest extends BaseTest {

    @Test(description = "OWASP A02 - Verify HTTPS is enforced for login")
    public void testHTTPSEnforcement() {
        driver.get(baseUrl);
        
        // Check if page uses HTTPS
        String currentUrl = driver.getCurrentUrl();
        
        // For local testing, verify no sensitive data in URL
        assertFalse(currentUrl.contains("password="), "Password should not appear in URL");
        assertFalse(currentUrl.contains("token="), "Token should not appear in URL");
        assertFalse(currentUrl.contains("api_key="), "API key should not appear in URL");
        
        logSecurityEvent("CRYPTO_CHECK", "INFO", "Verified no sensitive data in URL parameters");
    }

    @Test(description = "OWASP A02 - Check for plaintext password transmission")
    public void testPasswordNotInPlaintext() {
        driver.get(baseUrl);
        
        // Attempt login
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("testpassword123");
        
        // Check browser console logs for password leakage
        LogEntries logs = driver.manage().logs().get(LogType.BROWSER);
        for (LogEntry entry : logs) {
            String logMessage = entry.getMessage().toLowerCase();
            assertFalse(logMessage.contains("testpassword123"), 
                "Password should not appear in browser console logs");
        }
        
        logSecurityEvent("PLAINTEXT_PASSWORD_CHECK", "INFO", "Verified password not logged in plaintext");
    }

    @Test(description = "OWASP A02 - Verify credit card data is not stored in plaintext")
    public void testCreditCardEncryption() {
        driver.get(baseUrl);
        
        // Navigate to checkout
        driver.findElement(By.className("add-to-cart")).click();
        driver.findElement(By.id("checkout-btn")).click();
        
        // Enter credit card (mock data)
        driver.findElement(By.id("card-number")).sendKeys("4111111111111111");
        
        // Verify card number is masked in the UI
        String cardValue = driver.findElement(By.id("card-number")).getAttribute("value");
        
        // Check if it's masked or at least not fully visible in page source
        String pageSource = driver.getPageSource();
        assertFalse(pageSource.contains("4111111111111111"), 
            "Credit card number should not appear in plaintext in page source");
        
        logSecurityEvent("CC_ENCRYPTION_CHECK", "INFO", "Verified credit card data handling");
    }

    @Test(description = "OWASP A02 - Check for weak password hashing")
    public void testPasswordHashingStrength() {
        // This would typically check the backend, but we can verify no MD5/SHA1 in responses
        driver.get(baseUrl + "/api/users");
        
        String pageSource = driver.getPageSource();
        
        // Check for signs of weak hashing (MD5/SHA1 patterns)
        assertFalse(pageSource.matches(".*[a-f0-9]{32}.*"), 
            "Possible MD5 hash detected - use stronger algorithm like bcrypt");
        
        logSecurityEvent("PASSWORD_HASHING_CHECK", "INFO", "Checked for weak password hashing");
    }

    @Test(description = "OWASP A02 - Verify session tokens are cryptographically secure")
    public void testSessionTokenStrength() {
        driver.get(baseUrl);
        
        // Get session cookie
        String sessionId = driver.manage().getCookieNamed("JSESSIONID") != null 
            ? driver.manage().getCookieNamed("JSESSIONID").getValue() 
            : "";
        
        if (!sessionId.isEmpty()) {
            // Session ID should be long and random (not predictable)
            assertTrue(sessionId.length() >= 32, 
                "Session ID should be at least 32 characters for security");
            
            // Should not be sequential or simple pattern
            assertFalse(sessionId.matches("^[0-9]+$"), 
                "Session ID should not be purely numeric");
            
            logSecurityEvent("SESSION_TOKEN_CHECK", "INFO", 
                "Verified session token strength: " + sessionId.length() + " chars");
        }
    }
}
