package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.TimeoutException;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AccessControlTest extends BaseTest {

    @Test(priority = 1, description = "OWASP A01 - Test horizontal access control (User A accessing User B's cart)")
    public void testHorizontalAccessControl() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // ===== USER A: Login as testuser and add item to cart =====
        loginUser(wait, "testuser", "password123");
        ensureCartHasItem(wait);

        // Capture cart item ID for User A
        String cartItemId = driver.findElement(By.name("cartItemId")).getDomProperty("value");

        // Start a clean browser session for User B
        driver.manage().deleteAllCookies();
        
        // ===== USER B: Login as different user (paymentuser) =====
        loginUser(wait, "paymentuser", "Paym3nt@123");
        
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
        RestAssured.baseURI = baseUrl;

        // Login as testuser using API to keep the flow stable in headless runs.
        Response loginResponse = RestAssured
            .given()
            .redirects().follow(false)
            .formParam("username", "testuser")
            .formParam("password", "password123")
            .post("/perform_login");

        String sessionId = loginResponse.getCookie("JSESSIONID");
        String csrfToken = loginResponse.getCookie("XSRF-TOKEN");
        Assert.assertNotNull(sessionId, "Expected session cookie after login");

        Response productsResponse = RestAssured
            .given()
            .cookie("JSESSIONID", sessionId)
            .get("/products");
        String productsHtml = productsResponse.getBody().asString();
        if (csrfToken == null || csrfToken.isBlank()) {
            csrfToken = extractHiddenValue(productsHtml, "_csrf");
        }
        String productId = extractHiddenValue(productsHtml, "productId");
        Assert.assertNotNull(productId, "Expected product id in products page");
        Assert.assertNotNull(csrfToken, "Expected CSRF token for cart update");

        Response addResponse = RestAssured
            .given()
            .redirects().follow(false)
            .cookie("JSESSIONID", sessionId)
            .cookie("XSRF-TOKEN", csrfToken)
            .header("X-XSRF-TOKEN", csrfToken)
            .formParam("_csrf", csrfToken)
            .formParam("productId", productId)
            .formParam("quantity", 1)
            .post("/cart/add");
        Assert.assertTrue(addResponse.statusCode() == 200 || addResponse.statusCode() == 302,
            "Add-to-cart should succeed");

        Response checkoutResponse = RestAssured
            .given()
            .redirects().follow(false)
            .cookie("JSESSIONID", sessionId)
            .cookie("XSRF-TOKEN", csrfToken)
            .header("X-XSRF-TOKEN", csrfToken)
            .formParam("_csrf", csrfToken)
            .formParam("cardNumber", "4532123456789012")
            .formParam("cardName", "Test User")
            .formParam("expiryDate", "12/25")
            .formParam("cvv", "123")
            .post("/checkout/process");

        Assert.assertEquals(checkoutResponse.statusCode(), 200, "Checkout should return confirmation HTML");
        String body = checkoutResponse.getBody().asString();
        Matcher matcher = Pattern.compile("Transaction ID:\\s*<strong>(\\d+)</strong>").matcher(body);
        Assert.assertTrue(matcher.find(), "Checkout confirmation should include a transaction id");
        Long orderId = Long.valueOf(matcher.group(1));

        // Login as paymentuser and attempt to access testuser order
        Response paymentLogin = RestAssured
            .given()
            .redirects().follow(false)
            .formParam("username", "paymentuser")
            .formParam("password", "Paym3nt@123")
            .post("/perform_login");
        String paymentSessionId = paymentLogin.getCookie("JSESSIONID");
        Assert.assertNotNull(paymentSessionId, "Expected session cookie for paymentuser");

        Response response = RestAssured
            .given()
            .cookie("JSESSIONID", paymentSessionId)
            .get("/orders/" + orderId);

        Assert.assertEquals(response.statusCode(), 403,
            "User B should not access User A's order");
        assertSecurityEventLogged("ACCESS_CONTROL_VIOLATION");
    }
    
    @Test(priority = 3, description = "OWASP A01 - Test parameter tampering for authorization bypass")
    public void testParameterTamperingAuthorizationBypass() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        loginUser(wait, "testuser", "password123");
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
        loginUser(wait, "testuser", "password123");
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

    private void ensureCartHasItem(WebDriverWait wait) {
        addFirstProductToCart(wait);
        driver.get(baseUrl + "/cart");
        if (driver.getPageSource().contains("Your cart is empty")) {
            forceAddToCartViaApi(wait);
            driver.get(baseUrl + "/cart");
        }
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("form[action='/cart/remove']")));
    }

    private void addFirstProductToCart(WebDriverWait wait) {
        driver.get(baseUrl + "/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("button.add-to-cart")));
        driver.findElements(By.cssSelector("button.add-to-cart")).get(0).click();
    }

    private void forceAddToCartViaApi(WebDriverWait wait) {
        driver.get(baseUrl + "/products");
        wait.until(ExpectedConditions.presenceOfElementLocated(By.cssSelector("button.add-to-cart")));
        String productId = driver.findElements(By.name("productId")).get(0).getDomProperty("value");
        String csrfToken = driver.findElement(By.name("_csrf")).getDomProperty("value");
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Cookie csrfCookie = driver.manage().getCookieNamed("XSRF-TOKEN");

        RestAssured.baseURI = baseUrl;
        RestAssured.given()
            .cookie("JSESSIONID", sessionCookie != null ? sessionCookie.getValue() : "")
            .cookie("XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
            .header("X-XSRF-TOKEN", csrfCookie != null ? csrfCookie.getValue() : "")
            .formParam("_csrf", csrfToken)
            .formParam("productId", productId)
            .formParam("quantity", 1)
            .post("/cart/add");
    }

    private void loginUser(WebDriverWait wait, String username, String password) {
        WebDriverWait loginWait = new WebDriverWait(driver, Duration.ofSeconds(20));
        for (int attempt = 0; attempt < 2; attempt++) {
            driver.get(baseUrl + "/login");
            loginWait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
            driver.findElement(By.name("username")).clear();
            driver.findElement(By.name("username")).sendKeys(username);
            driver.findElement(By.name("password")).clear();
            driver.findElement(By.name("password")).sendKeys(password);
            driver.findElement(By.xpath("//button[@type='submit']")).click();

            try {
                loginWait.until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));
                return;
            } catch (TimeoutException ignored) {
                driver.manage().deleteAllCookies();
            }
        }
        // Fallback: login via REST and inject session cookies for stability in demos.
        RestAssured.baseURI = baseUrl;
        Response response = RestAssured
            .given()
            .redirects().follow(false)
            .formParam("username", username)
            .formParam("password", password)
            .post("/perform_login");

        String sessionId = response.getCookie("JSESSIONID");
        String csrfToken = response.getCookie("XSRF-TOKEN");
        if (sessionId == null || sessionId.isBlank()) {
            throw new TimeoutException("Login failed for user: " + username);
        }

        driver.get(baseUrl + "/");
        driver.manage().addCookie(new Cookie("JSESSIONID", sessionId));
        if (csrfToken != null && !csrfToken.isBlank()) {
            driver.manage().addCookie(new Cookie("XSRF-TOKEN", csrfToken));
        }
        driver.get(baseUrl + "/products");
        loginWait.until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));
    }

    private String extractHiddenValue(String html, String name) {
        if (html == null) {
            return null;
        }
        Pattern pattern = Pattern.compile("name=\"" + Pattern.quote(name) + "\"\\s+value=\"(\\d+|[^\"]+)\"");
        Matcher matcher = pattern.matcher(html);
        return matcher.find() ? matcher.group(1) : null;
    }
    
}
