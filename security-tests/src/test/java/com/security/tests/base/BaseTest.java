package com.security.tests.base;

import io.github.bonigarcia.wdm.WebDriverManager;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.firefox.FirefoxDriver;
import org.openqa.selenium.firefox.FirefoxOptions;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeSuite;
import com.security.tests.utils.SecurityEventLogger;
import com.security.tests.utils.ConfigReader;

/**
 * Base test class that all security tests extend from.
 * Handles WebDriver initialization, teardown, and common setup.
 */
public class BaseTest {
    
    protected WebDriver driver;
    protected String baseUrl;
    protected SecurityEventLogger eventLogger;
    
    @BeforeSuite
    public void suiteSetup() {
        // Initialize security event database
        SecurityEventLogger.initializeDatabase();
        
        // Load configuration
        baseUrl = System.getProperty("baseUrl", "http://localhost:8080");
    }
    
    @BeforeMethod
    public void setUp() {
        String browser = System.getProperty("browser", "chrome").toLowerCase();
        boolean headless = Boolean.parseBoolean(System.getProperty("headless", "false"));
        
        switch (browser) {
            case "firefox":
                WebDriverManager.firefoxdriver().setup();
                FirefoxOptions firefoxOptions = new FirefoxOptions();
                if (headless) {
                    firefoxOptions.addArguments("--headless");
                }
                driver = new FirefoxDriver(firefoxOptions);
                break;
                
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
                driver = new ChromeDriver(chromeOptions);
                break;
        }
        
        driver.manage().window().maximize();
        eventLogger = new SecurityEventLogger();
    }
    
    @AfterMethod
    public void tearDown() {
        if (driver != null) {
            driver.quit();
        }
    }
    
    protected void navigateToUrl(String path) {
        driver.get(baseUrl + path);
    }
}
