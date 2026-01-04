package com.security.tests.auth;

import com.security.tests.base.BaseTest;
import org.openqa.selenium.By;
import org.openqa.selenium.Cookie;
import org.openqa.selenium.JavascriptExecutor; 
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;         
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;
import io.github.bonigarcia.wdm.WebDriverManager;
import java.time.Duration;
import org.testng.Assert;
import org.testng.annotations.Test;


public class SessionHijackingTest extends BaseTest {
    
    @Test(priority = 1, description = "Test session hijacking by stealing session cookie")
    public void testSessionCookieStealing() {
        
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        
        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));
        
        
        Cookie sessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        Assert.assertNotNull(sessionCookie, "Session cookie should be present after login");
        
        
        boolean isHttpOnly = sessionCookie.isHttpOnly();
        Assert.assertTrue(isHttpOnly, 
            "Session cookie should have HttpOnly flag to prevent XSS-based hijacking");
        
        
        boolean isSecure = sessionCookie.isSecure();
        
        
        if (!isHttpOnly || (!isSecure && !baseUrl.contains("localhost"))) {
            logSecurityEvent("INSECURE_SESSION_COOKIE", "HIGH",
                "Session hijacking vulnerability - Session cookie lacks proper security flags (HttpOnly: " + 
                isHttpOnly + ", Secure: " + isSecure + ") for user: testuser");
        }
    }
    
    @Test(priority = 2, description = "Test session reuse after logout")
    public void testSessionReuseAfterLogout() {
        
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();
        
        
        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));

        
        Cookie oldSessionCookie = driver.manage().getCookieNamed("JSESSIONID");
        String oldSessionId = oldSessionCookie != null ? oldSessionCookie.getValue() : "";
        
        
        navigateToUrl("/products"); 
        
        
        WebElement logoutBtn = driver.findElement(By.id("logoutButton"));
        ((JavascriptExecutor) driver).executeScript("arguments[0].click();", logoutBtn);
        
        
        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.urlContains("/login"));

        
        if (oldSessionCookie != null) {
            driver.manage().addCookie(oldSessionCookie);
        }
        
        
        navigateToUrl("/account");
        
        
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
        navigateToUrl("/login");
        driver.findElement(By.id("username")).sendKeys("testuser");
        driver.findElement(By.id("password")).sendKeys("password123");
        driver.findElement(By.xpath("//button[@type='submit']")).click();

        new WebDriverWait(driver, Duration.ofSeconds(10))
            .until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));

        WebDriver secondDriver = createSecondaryDriver();
        try {
            secondDriver.get(baseUrl + "/login");
            secondDriver.findElement(By.id("username")).sendKeys("testuser");
            secondDriver.findElement(By.id("password")).sendKeys("password123");
            secondDriver.findElement(By.xpath("//button[@type='submit']")).click();

            new WebDriverWait(secondDriver, Duration.ofSeconds(10))
                .until(ExpectedConditions.not(ExpectedConditions.urlContains("/login")));
        } finally {
            secondDriver.quit();
        }

        navigateToUrl("/checkout");
        boolean redirectedToLogin = driver.getCurrentUrl().contains("/login") ||
            driver.getPageSource().toLowerCase().contains("login");

        Assert.assertTrue(redirectedToLogin,
            "First session should be invalidated after a second login");

        logSecurityEvent("CONCURRENT_SESSION_TEST", "MEDIUM",
            "Verified concurrent session handling for user: testuser");
    }

    private WebDriver createSecondaryDriver() {
        String browser = System.getProperty("browser", "chrome").toLowerCase();
        boolean headless = Boolean.parseBoolean(System.getProperty("headless", "false"));

        switch (browser) {
            case "firefox":
                WebDriverManager.firefoxdriver().setup();
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                if (headless) {
                    firefoxOptions.addArguments("--headless");
                }
                return new FirefoxDriver(firefoxOptions);
            case "chrome":
            default:
                WebDriverManager.chromedriver().setup();
                ChromeOptions chromeOptions = new ChromeOptions();
                if (headless) {
                    chromeOptions.addArguments("--headless=new");
                }
                chromeOptions.addArguments("--no-sandbox");
                chromeOptions.addArguments("--disable-dev-shm-usage");
                chromeOptions.addArguments("--disable-gpu");
                chromeOptions.addArguments("--remote-allow-origins=*");
                return new ChromeDriver(chromeOptions);
        }
    }
}
