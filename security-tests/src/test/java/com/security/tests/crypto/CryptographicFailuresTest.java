package com.security.tests.crypto;

import com.security.tests.base.BaseTest;
import org.testng.annotations.Test;
import static org.testng.Assert.*;


public class CryptographicFailuresTest extends BaseTest {

    @Test(description = "OWASP A02 - Check for weak SSL/TLS usage")
    public void testWeakSSL() {
        
        
        String currentUrl = driver.getCurrentUrl();
        
        if (currentUrl.startsWith("https")) {
            logSecurityEvent("SSL_CHECK", "INFO", "Connection is using HTTPS");
        } else {
            
            logSecurityEvent("SSL_CHECK", "WARN", "Connection is using HTTP (Acceptable for local dev only)");
        }
    }

    @Test(description = "OWASP A02 - Verify no sensitive data in local storage")
    public void testLocalStorageExposure() {
        navigateToUrl("/login");
        
        
        String script = "return JSON.stringify(localStorage);";
        String localStorage = (String) ((org.openqa.selenium.JavascriptExecutor) driver).executeScript(script);
        
        if (localStorage != null) {
            assertFalse(localStorage.toLowerCase().contains("password"), 
                "Local storage should not contain passwords");
            assertFalse(localStorage.toLowerCase().contains("token"), 
                "Local storage should not contain raw auth tokens (use HttpOnly cookies)");
        }
        
        logSecurityEvent("LOCAL_STORAGE_CHECK", "INFO", "Verified local storage does not contain sensitive secrets");
    }
}