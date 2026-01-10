package com.security.tests.injection;

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

public class SSRFTest extends BaseTest {

    @Test(priority = 1, description = "OWASP A10 - Test SSRF via file:// protocol")
    public void testSSRFFileProtocol() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        waitForRateLimitReset();
        
        // ===== SSRF ATTACK: Attempt to read local files via file:// protocol =====
        RestAssured.baseURI = baseUrl;
        
        // Test various file:// payloads
        String[] filePayloads = {
            "file:///etc/passwd",
            "file:///C:/Windows/System32/drivers/etc/hosts",
            "file://localhost/etc/passwd",
            "file:///proc/self/environ"
        };
        
        for (String fileUrl : filePayloads) {
            // If application has any endpoint that fetches external resources (e.g., product image URL)
            // This simulates attempting to supply a malicious URL
            Response response = RestAssured
                .given()
                .cookie("JSESSIONID", sessionCookie.getValue())
                .queryParam("imageUrl", fileUrl)
                .get("/products");

            if (response.statusCode() == 429) {
                waitForRateLimitReset();
                response = RestAssured
                    .given()
                    .cookie("JSESSIONID", sessionCookie.getValue())
                    .queryParam("imageUrl", fileUrl)
                    .get("/products");
            }

            Assert.assertEquals(response.statusCode(), 400,
                "SSRF file payload should be blocked: " + fileUrl);
        }
        assertSecurityEventLogged("SSRF_ATTEMPT");
    }
    
    @Test(priority = 2, description = "OWASP A10 - Test SSRF via localhost/internal network access")
    public void testSSRFLocalhostAccess() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        waitForRateLimitReset();
        
        // ===== SSRF ATTACK: Attempt to access internal services =====
        RestAssured.baseURI = baseUrl;
        
        String[] localhostPayloads = {
            "http://localhost:8080/api/security/events",
            "http://127.0.0.1:8080/api/security/dashboard",
            "http://0.0.0.0:8080/admin",
            "http://[::1]:8080/api/admin"
        };
        
        for (String internalUrl : localhostPayloads) {
            Response response = RestAssured
                .given()
                .cookie("JSESSIONID", sessionCookie.getValue())
                .queryParam("imageUrl", internalUrl)
                .get("/products");

            if (response.statusCode() == 429) {
                waitForRateLimitReset();
                response = RestAssured
                    .given()
                    .cookie("JSESSIONID", sessionCookie.getValue())
                    .queryParam("imageUrl", internalUrl)
                    .get("/products");
            }

            // Application should block localhost/127.0.0.1 access
            Assert.assertEquals(response.statusCode(), 400,
                "SSRF localhost payload should be blocked: " + internalUrl);
        }
        assertSecurityEventLogged("SSRF_ATTEMPT");
    }
    
    @Test(priority = 3, description = "OWASP A10 - Test SSRF via cloud metadata endpoints")
    public void testSSRFCloudMetadata() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        waitForRateLimitReset();
        
        // ===== SSRF ATTACK: Attempt to access cloud provider metadata =====
        RestAssured.baseURI = baseUrl;
        
        String[] cloudMetadataUrls = {
            "http://169.254.169.254/latest/meta-data/",              // AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",   // GCP metadata
            "http://169.254.169.254/metadata/instance",              // Azure metadata
            "http://169.254.170.2/v2/metadata"                       // ECS task metadata
        };
        
        for (String metadataUrl : cloudMetadataUrls) {
            Response response = RestAssured
                .given()
                .cookie("JSESSIONID", sessionCookie.getValue())
                .queryParam("imageUrl", metadataUrl)
                .get("/products");

            if (response.statusCode() == 429) {
                waitForRateLimitReset();
                response = RestAssured
                    .given()
                    .cookie("JSESSIONID", sessionCookie.getValue())
                    .queryParam("imageUrl", metadataUrl)
                    .get("/products");
            }

            // Application should block access to cloud metadata endpoints
            // This is critical for cloud deployments
            Assert.assertEquals(response.statusCode(), 400,
                "SSRF metadata payload should be blocked: " + metadataUrl);
        }
        assertSecurityEventLogged("SSRF_ATTEMPT");
    }
    
    @Test(priority = 4, description = "OWASP A10 - Test SSRF via private IP ranges")
    public void testSSRFPrivateIPRanges() {
        WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
        
        // Login as regular user
        driver.get(baseUrl + "/login");
        wait.until(ExpectedConditions.visibilityOfElementLocated(By.name("username")));
        driver.findElement(By.name("username")).sendKeys("testuser");
        driver.findElement(By.name("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        wait.until(ExpectedConditions.urlContains("/products"));
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        waitForRateLimitReset();
        
        // ===== SSRF ATTACK: Attempt to access private network ranges =====
        RestAssured.baseURI = baseUrl;
        
        String[] privateIpUrls = {
            "http://10.0.0.1/admin",           // Class A private range
            "http://172.16.0.1/api",           // Class B private range
            "http://192.168.1.1/router",       // Class C private range
            "http://192.168.0.100:8080/api"    // Home network typical IP
        };
        
        for (String privateUrl : privateIpUrls) {
            Response response = RestAssured
                .given()
                .cookie("JSESSIONID", sessionCookie.getValue())
                .queryParam("imageUrl", privateUrl)
                .get("/products");

            if (response.statusCode() == 429) {
                waitForRateLimitReset();
                response = RestAssured
                    .given()
                    .cookie("JSESSIONID", sessionCookie.getValue())
                    .queryParam("imageUrl", privateUrl)
                    .get("/products");
            }

            // Application should block private IP ranges
            // Prevents access to internal corporate networks
            Assert.assertEquals(response.statusCode(), 400,
                "SSRF private IP payload should be blocked: " + privateUrl);
        }
        assertSecurityEventLogged("SSRF_ATTEMPT");
    }

    private void waitForRateLimitReset() {
        RestAssured.baseURI = baseUrl;
        for (int i = 0; i < 8; i++) {
            Response response = RestAssured.given().get("/products");
            if (response.statusCode() != 429) {
                return;
            }
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }
}
