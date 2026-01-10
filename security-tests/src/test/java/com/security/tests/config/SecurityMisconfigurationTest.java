package com.security.tests.config;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.http.Method;
import io.restassured.response.Response;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.annotations.Test;
import static org.testng.Assert.*;

import java.time.Duration;
public class SecurityMisconfigurationTest extends BaseTest {



    @Test(description = "OWASP A02:2025 - Suppress verbose error details")
    public void testVerboseErrorMessages() {
        driver.get(baseUrl + "/nonexistent-page-12345");
        
        String pageSource = driver.getPageSource();
        
        
        assertFalse(pageSource.contains("java.lang."), 
            "Java stack traces should not be exposed to users");
        assertFalse(pageSource.contains("Exception"), 
            "Exception details should not be visible");
        assertFalse(pageSource.contains("at com.security"), 
            "Package names should not be exposed in errors");
        assertFalse(pageSource.contains("line "), 
            "Line numbers should not be exposed");
        
    }



    @Test(description = "OWASP A02:2025 - Reject default credentials")
    public void testDefaultCredentials() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        
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
            
            
            driver.findElement(By.xpath("//button[@type='submit']")).click();
            
            
            String currentUrl = driver.getCurrentUrl();
            assertFalse(currentUrl.contains("/dashboard") || currentUrl.contains("/home") || currentUrl.contains("/checkout"),
                "Default credentials " + cred[0] + "/" + cred[1] + " should not work");
            
            
            if (!currentUrl.contains("/login")) {
                 driver.get(baseUrl + "/login"); 
            }
        }
        
    }



    @Test(description = "OWASP A02:2025 - Disable directory listing")
    public void testDirectoryListing() {
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
            
            
            assertFalse(pageSource.contains("Index of") || pageSource.contains("Directory Listing"),
                "Directory listing should be disabled for " + dir);
        }
        
    }



    @Test(description = "OWASP A02:2025 - Set baseline security headers")
    public void testSecurityHeaders() {
        RestAssured.baseURI = baseUrl;
        Response response = RestAssured.given()
            .redirects().follow(false)
            .get("/");

        // X-Content-Type-Options should always be set
        String contentTypeOptions = response.getHeader("X-Content-Type-Options");
        boolean hasNoSniff = contentTypeOptions != null && contentTypeOptions.toLowerCase().contains("nosniff");
        assertTrue(hasNoSniff,
            "X-Content-Type-Options should be set to nosniff");

        // X-Frame-Options or CSP for clickjacking protection
        String xFrameOptions = response.getHeader("X-Frame-Options");
        String csp = response.getHeader("Content-Security-Policy");
        boolean hasClickjackingProtection = (xFrameOptions != null && !xFrameOptions.isBlank())
            || (csp != null && csp.toLowerCase().contains("frame-ancestors"));
        assertTrue(hasClickjackingProtection,
            "Clickjacking protection should be enabled via X-Frame-Options or CSP frame-ancestors");

        // HSTS should be enabled over HTTPS
        if (baseUrl.startsWith("https")) {
            String hsts = response.getHeader("Strict-Transport-Security");
            assertTrue(hsts != null && !hsts.isBlank(),
                "Strict-Transport-Security should be enabled over HTTPS");

        }

    }



    @Test(description = "OWASP A02:2025 - Block public admin endpoints")
    public void testExposedAdminInterfaces() {
        String[] adminUrls = {
            "/admin",
            "/administrator",
            "/manage",
            "/console",
            "/actuator" 
        };
        
        for (String adminUrl : adminUrls) {
            driver.get(baseUrl + adminUrl);
            
            
            String pageSource = driver.getPageSource();
            assertFalse(pageSource.contains("Admin Panel") || pageSource.contains("Management Console") || pageSource.contains("actuator/"),
                "Admin interface at " + adminUrl + " should not be publicly accessible");
        }
        
    }



    @Test(description = "OWASP A02:2025 - Avoid version disclosure")
    public void testInformationDisclosure() {
        driver.get(baseUrl);
        
        
        String pageSource = driver.getPageSource();
        
        assertFalse(pageSource.contains("Spring Boot"), 
            "Framework version should not be disclosed");
        assertFalse(pageSource.contains("Tomcat/"), 
            "Server version should not be disclosed");
        assertFalse(pageSource.matches(".*Java/[0-9.]+.*"), 
            "Java version should not be disclosed");
        
    }



    @Test(description = "OWASP A02:2025 - Disable unnecessary HTTP methods")
    public void testUnnecessaryHTTPMethods() {
        RestAssured.baseURI = baseUrl;

        Response traceResponse = RestAssured.given().request(Method.TRACE, "/");
        assertMethodDisabled(traceResponse, "TRACE", isDemoMode());

        Response putResponse = RestAssured.given().request(Method.PUT, "/");
        assertMethodDisabled(putResponse, "PUT", isDemoMode());

        Response deleteResponse = RestAssured.given().request(Method.DELETE, "/");
        assertMethodDisabled(deleteResponse, "DELETE", isDemoMode());

        String allowHeader = traceResponse.getHeader("Allow");
        if (allowHeader != null) {
            assertFalse(allowHeader.toUpperCase().contains("TRACE"),
                "TRACE should not be advertised in Allow header");
        }

    }



    private void assertMethodDisabled(Response response, String method, boolean demoMode) {
        int status = response.statusCode();
        boolean disabled;
        if (demoMode) {
            disabled = status < 200 || status >= 300;
        } else {
            disabled = (status >= 300 && status < 400)
                || status == 400
                || status == 401
                || status == 403
                || status == 404
                || status == 405;
        }
        assertTrue(disabled, method + " should be disabled (status: " + status + ")");
    }



    private boolean isDemoMode() {
        String env = System.getProperty("env", "demo").toLowerCase();
        if (env.contains("demo") || env.contains("dev") || env.contains("local")) {
            return true;
        }
        return baseUrl != null && baseUrl.toLowerCase().startsWith("http://");
    }
    
    @Test(priority = 10, description = "OWASP A05:2021 - Verify stack traces not exposed in error responses")
    public void testStackTraceExposure() {
        RestAssured.baseURI = baseUrl;
        
        // Skip if running in demo mode (localhost) - stack traces may be intentionally shown for debugging
        if (isDemoMode()) {
            System.out.println("Skipping stack trace exposure test - running in demo mode");
            return;
        }
        
        // Trigger various error conditions and check for stack trace leakage
        String[] errorUrls = {
            "/api/nonexistent",
            "/products?search=test&currency=INVALID",
            "/cart/update?itemId=999999&quantity=-1",
            "/api/security/events?userId=abc"  // Invalid parameter type
        };
        
        boolean foundStackTrace = false;
        String exposedUrl = null;
        String stackTraceSnippet = null;
        
        for (String url : errorUrls) {
            try {
                Response response = RestAssured.given()
                    .when()
                    .get(url);
                
                String responseBody = response.getBody().asString();
                
                // Check for common stack trace indicators
                String[] stackTracePatterns = {
                    "Exception",
                    "at com.security",
                    "at java.lang",
                    "at org.springframework",
                    "Caused by:",
                    ".java:",
                    "Stack trace:",
                    "Stacktrace:"
                };
                
                for (String pattern : stackTracePatterns) {
                    if (responseBody.contains(pattern)) {
                        foundStackTrace = true;
                        exposedUrl = url;
                        stackTraceSnippet = pattern;
                        break;
                    }
                }
                
                if (foundStackTrace) {
                    break;
                }
                
            } catch (Exception e) {
                // Continue checking other URLs
            }
        }
        
        if (foundStackTrace) {
            // Log security event - stack trace exposed
            com.security.tests.utils.SecurityEvent event = 
                com.security.tests.utils.SecurityEvent.createMediumSeverityEvent(
                    "SECURITY_MISCONFIGURATION",
                    "anonymous",
                    "Detailed error messages reveal internal application structure",
                    "Stack trace exposed at '" + exposedUrl + "' (found: '" + stackTraceSnippet + "')"
                );
            eventLogger.logSecurityEvent(event);
            
            fail("Stack trace exposed in production error response at " + exposedUrl);
        }
        
        System.out.println("? No stack traces exposed in error responses");
    }
    
    @Test(priority = 11, description = "OWASP A05:2021 - Verify OPTIONS method doesn't leak endpoint information")
    public void testOptionsMethodInformationLeakage() {
        RestAssured.baseURI = baseUrl;
        
        Response response = RestAssured.given()
            .request(Method.OPTIONS, "/products");
        
        String allowHeader = response.getHeader("Allow");
        
        // OPTIONS should either be disabled or return minimal information
        if (allowHeader != null && !allowHeader.isEmpty()) {
            // Check if it's leaking too much information
            String[] suspiciousMethods = {"TRACE", "CONNECT", "PATCH"};
            
            for (String method : suspiciousMethods) {
                if (allowHeader.toUpperCase().contains(method)) {
                    // Log security event - unnecessary HTTP methods advertised
                    com.security.tests.utils.SecurityEvent event = 
                        com.security.tests.utils.SecurityEvent.createMediumSeverityEvent(
                            "SECURITY_MISCONFIGURATION",
                            "anonymous",
                            "Allow header should only include required methods (GET, POST, etc.)",
                            "OPTIONS method exposes unnecessary HTTP method: " + method
                        );
                    eventLogger.logSecurityEvent(event);
                    
                    System.out.println("? Warning: OPTIONS method advertises unnecessary method: " + method);
                }
            }
        }
        
        // Check if response body contains detailed API documentation
        String responseBody = response.getBody().asString();
        if (responseBody.contains("swagger") || responseBody.contains("openapi") || 
            responseBody.contains("endpoint") || responseBody.contains("parameter")) {
            
            com.security.tests.utils.SecurityEvent event = 
                com.security.tests.utils.SecurityEvent.createMediumSeverityEvent(
                    "INFO_DISCLOSURE",
                    "anonymous",
                    "API metadata should not be publicly accessible in production",
                    "OPTIONS method exposes API documentation or endpoint details"
                );
            eventLogger.logSecurityEvent(event);
            
            System.out.println("? Warning: OPTIONS method exposes API documentation");
        }
        
        System.out.println("? OPTIONS method check completed");
    }

}
