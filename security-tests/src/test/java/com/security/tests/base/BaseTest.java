package com.security.tests.base;
import java.time.Duration;
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
import com.security.tests.utils.SecurityEvent;


public class BaseTest {
    
    protected WebDriver driver;
    
    protected String baseUrl = "http://localhost:8080"; 
    protected SecurityEventLogger eventLogger;
    
    @BeforeSuite
    public void suiteSetup() {
        
        SecurityEventLogger.initializeDatabase();
    }
    
    @BeforeMethod
    public void setUp() {
        
        String propUrl = System.getProperty("baseUrl");
        if (propUrl != null && !propUrl.isEmpty()) {
            this.baseUrl = propUrl;
        }

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
                
                chromeOptions.addArguments("--remote-allow-origins=*");
                driver = new ChromeDriver(chromeOptions);
                break;
        }
        
        driver.manage().window().maximize();
        
        
        driver.manage().timeouts().implicitlyWait(Duration.ofSeconds(20));
        
        
        driver.manage().timeouts().pageLoadTimeout(Duration.ofSeconds(60));
        
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
    
    
    protected void logSecurityEvent(String eventType, String severity, String description) {
        if (eventLogger != null) {
            SecurityEvent event = new SecurityEvent();
            event.setEventType(eventType);
            event.setSeverity(severity);
            event.setEventDetails(description);
            event.setUsername("test-user");
            event.setIpAddress("127.0.0.1");
            eventLogger.logSecurityEvent(event);
        }
    }
}
