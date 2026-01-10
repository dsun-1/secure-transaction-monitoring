package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;

public class AccessControlTest extends BaseTest {

    @Test(priority = 1, description = "OWASP A01 - Test horizontal access control (User A accessing User B's cart)")
    public void testHorizontalAccessControl() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // ===== USER A: Login as testuser and add item to cart =====
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        driver.get(baseUrl + "/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.xpath("//button[contains(text(), 'Add to Cart')]")));
        driver.findElement(By.xpath("//button[contains(text(), 'Add to Cart')]")).click();

        // Capture cart item ID for User A
        driver.get(baseUrl + "/cart");
        if (driver.getPageSource().contains("Your cart is empty")) {
            driver.get(baseUrl + "/products");
            wait.until(ExpectedConditions.presenceOfElementLocated(By.xpath("//button[contains(text(), 'Add to Cart')]")));
            driver.findElement(By.xpath("//button[contains(text(), 'Add to Cart')]")).click();
            driver.get(baseUrl + "/cart");
        }
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("form[action='/cart/remove']")));
        String cartItemId = driver.findElement(By.name("cartItemId")).getAttribute("value");

        // Start a clean browser session for User B
        driver.manage().deleteAllCookies();
        
        // ===== USER B: Login as different user (paymentuser) =====
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("paymentuser");
        driver.findElement(By.name("password")).sendKeys("Paym3nt@123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // ===== ATTACK: User B tries to update User A's cart item =====
        RestAssured.baseURI = baseUrl;
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Cookie csrfCookie = driver.manage().getCookieNamed("XSRF-TOKEN");
        Assert.assertNotNull(sessionCookie, "Expected session cookie for paymentuser");
        Assert.assertNotNull(csrfCookie, "Expected CSRF cookie for paymentuser");

        Response response = RestAssured
            .given()
            .redirects().follow(false)
            .cookie("JSESSIONID", sessionCookie.getValue())
            .cookie("XSRF-TOKEN", csrfCookie.getValue())
            .header("X-XSRF-TOKEN", csrfCookie.getValue())
            .formParam("_csrf", csrfCookie.getValue())
            .formParam("cartItemId", cartItemId)
            .formParam("quantity", 2)
            .post("/cart/update");

        Assert.assertEquals(response.statusCode(), 403,
            "User B should not update User A's cart item");
        assertSecurityEventLogged("ACCESS_CONTROL_VIOLATION");
    }
    
    @Test(priority = 2, description = "OWASP A01 - Test IDOR (Insecure Direct Object Reference) in order access")
    public void testIDORVulnerability() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
         
        // Login as testuser
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // Add product to cart
        driver.get(baseUrl + "/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.xpath("//button[contains(text(), 'Add to Cart')]")));
        driver.findElement(By.xpath("//button[contains(text(), 'Add to Cart')]")).click();
        // Complete checkout to create an order
        driver.get(baseUrl + "/checkout");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("cardNumber")));
        driver.findElement(By.name("cardNumber")).sendKeys("4532123456789012");
        driver.findElement(By.name("cardName")).sendKeys("Test User");
        driver.findElement(By.name("expiryDate")).sendKeys("12/25");
        driver.findElement(By.name("cvv")).sendKeys("123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();

        wait.until(ExpectedConditions.visibilityOfElementLocated(By.cssSelector(".transaction-id strong")));
        String orderIdText = driver.findElement(By.cssSelector(".transaction-id strong")).getText();
        Long orderId = Long.valueOf(orderIdText.trim());

        // Start a clean browser session for User B
        driver.manage().deleteAllCookies();

        // Login as paymentuser and attempt to access testuser order
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("paymentuser");
        driver.findElement(By.name("password")).sendKeys("Paym3nt@123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        wait.until(ExpectedConditions.urlContains("/products"));

        RestAssured.baseURI = baseUrl;
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Response response = RestAssured
            .given()
            .cookie("JSESSIONID", sessionCookie.getValue())
            .get("/orders/" + orderId);

        Assert.assertEquals(response.statusCode(), 403,
            "User B should not access User A's order");
        assertSecurityEventLogged("ACCESS_CONTROL_VIOLATION");
    }
    
    @Test(priority = 3, description = "OWASP A01 - Test parameter tampering for authorization bypass")
    public void testParameterTamperingAuthorizationBypass() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        
        // ===== ATTACK: Try to bypass authorization with tampered parameters =====
        RestAssured.baseURI = baseUrl;
        
        // Test 1: Try to elevate privileges via role parameter
        Response roleResponse = RestAssured
            .given()
            .cookie("JSESSIONID", sessionCookie.getValue())
            .queryParam("role", "ADMIN")
            .get("/products");
        Assert.assertEquals(roleResponse.statusCode(), 200, "Role parameter should not change access");
        
        // Test 2: Try admin flag tampering
        Response adminFlagResponse = RestAssured
            .given()
            .cookie("JSESSIONID", sessionCookie.getValue())
            .queryParam("isAdmin", "true")
            .get("/products");
        Assert.assertEquals(adminFlagResponse.statusCode(), 200, "isAdmin parameter should not change access");
        
        // Test 3: Try HTTP header manipulation for role escalation
        Response headerRoleResponse = RestAssured
            .given()
            .cookie("JSESSIONID", sessionCookie.getValue())
            .header("X-User-Role", "ADMIN")
            .get("/products");
        Assert.assertEquals(headerRoleResponse.statusCode(), 200, "Header tampering should not change access");
        
        // Test 4: Try privilege level manipulation
        Response privilegeResponse = RestAssured
            .given()
            .cookie("JSESSIONID", sessionCookie.getValue())
            .header("X-Privilege-Level", "5")
            .get("/products");
        Assert.assertEquals(privilegeResponse.statusCode(), 200, "Privilege header should not change access");
        
        // This test demonstrates various parameter tampering vectors
        // In a secure app, these should be ignored or logged as violations
    }
    
    @Test(priority = 4, description = "OWASP A01 - Test forced browsing to restricted resources")
    public void testForcedBrowsing() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        
        // ===== ATTACK: Try to access admin endpoints by direct URL manipulation =====
        RestAssured.baseURI = baseUrl;
        
        String[] adminPaths = {
            "/admin",
            "/admin/users",
            "/admin/config",
            "/api/admin",
            "/api/security/dashboard",
            "/management",
            "/actuator/env"
        };
        
        for (String adminPath : adminPaths) {
            Response response = RestAssured
                .given()
                .cookie("JSESSIONID", sessionCookie.getValue())
                .get(adminPath);
            
            // If regular user can access admin endpoints, it's a forced browsing vulnerability
            Assert.assertNotEquals(response.statusCode(), 200,
                "Forced browsing should not succeed for: " + adminPath);
        }
    }
    
}
