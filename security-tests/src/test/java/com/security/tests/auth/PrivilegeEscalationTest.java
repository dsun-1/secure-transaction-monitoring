package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.response.Response;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.time.Duration;

public class PrivilegeEscalationTest extends BaseTest {

    @Test(priority = 1, description = "OWASP A01 - Test vertical privilege escalation to admin dashboard")
    public void testUserAccessingAdminDashboard() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user (USER role)
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        // Wait for successful login
        wait.until(ExpectedConditions.urlContains("/products"));
        
        // Get session cookie for API request
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        
        // Attempt to access admin-only endpoint
        RestAssured.baseURI = baseUrl;
        Response response = RestAssured
            .given()
            .config(RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false)))
            .cookie("JSESSIONID", sessionCookie.getValue())
            .get("/api/security/dashboard");
        
        // Verify access denied (403 Forbidden or 302 redirect to login)
        Assert.assertTrue(response.statusCode() == 403 || response.statusCode() == 302,
            "USER should not access ADMIN endpoint (got: " + response.statusCode() + ")");
        
        // Verify privilege escalation attempt was logged
        assertSecurityEventLogged("PRIVILEGE_ESCALATION_ATTEMPT");
    }
    
    @Test(priority = 2, description = "OWASP A01 - Test access to admin security events endpoint")
    public void testUserAccessingSecurityEvents() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        
        // Attempt to access security events endpoint (ADMIN only)
        RestAssured.baseURI = baseUrl;
        Response response = RestAssured
            .given()
            .config(RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false)))
            .cookie("JSESSIONID", sessionCookie.getValue())
            .get("/api/security/events");
        
        // Verify access denied
        Assert.assertTrue(response.statusCode() == 403 || response.statusCode() == 302,
            "USER should not access /api/security/events (got: " + response.statusCode() + ")");
        
        assertSecurityEventLogged("PRIVILEGE_ESCALATION_ATTEMPT");
    }
    
    @Test(priority = 3, description = "OWASP A01 - Verify admin can access protected endpoints")
    public void testAdminAccessToProtectedEndpoints() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as admin user (ADMIN role)
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("admin");
        driver.findElement(By.name("password")).sendKeys("admin123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        
        // Verify admin CAN access dashboard
        RestAssured.baseURI = baseUrl;
        Response dashboardResponse = RestAssured
            .given()
            .cookie("JSESSIONID", sessionCookie.getValue())
            .get("/api/security/dashboard");
        
        Assert.assertEquals(dashboardResponse.statusCode(), 200,
            "ADMIN should access dashboard successfully");
        
        // Verify admin CAN access security events
        Response eventsResponse = RestAssured
            .given()
            .cookie("JSESSIONID", sessionCookie.getValue())
            .get("/api/security/events");
        
        Assert.assertEquals(eventsResponse.statusCode(), 200,
            "ADMIN should access security events successfully");
    }
    
    @Test(priority = 4, description = "OWASP A01 - Test unauthenticated access to admin endpoints")
    public void testUnauthenticatedAccessToAdminEndpoints() {
        RestAssured.baseURI = baseUrl;
        
        // Attempt to access admin dashboard without authentication
        Response dashboardResponse = RestAssured
            .given()
            .config(RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false)))
            .get("/api/security/dashboard");
        
        // Should get 401 Unauthorized or 302 redirect
        Assert.assertTrue(dashboardResponse.statusCode() == 401 || dashboardResponse.statusCode() == 302,
            "Unauthenticated user should not access admin endpoints (got: " + dashboardResponse.statusCode() + ")");
        
        // Attempt to access security events without authentication
        Response eventsResponse = RestAssured
            .given()
            .config(RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false)))
            .get("/api/security/events");
        
        Assert.assertTrue(eventsResponse.statusCode() == 401 || eventsResponse.statusCode() == 302,
            "Unauthenticated user should not access /api/security/events (got: " + eventsResponse.statusCode() + ")");
    }
}
