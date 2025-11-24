package com.security.ecommerce.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

@Service
public class AlertManagerService {

    private static final Logger logger = LoggerFactory.getLogger(AlertManagerService.class);

    private final JavaMailSender mailSender;

    // Comma-separated recipients
    @Value("${alert.email.recipients:}")
    private String emailRecipients;

    @Value("${alert.email.from:alerts@example.com}")
    private String emailFrom;

    public AlertManagerService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * Send a simple email alert. Logs debug information for troubleshooting.
     */
    public boolean sendEmailAlert(String subject, String body) {
        List<String> recipients = Arrays.asList(emailRecipients.split(","));
        logger.debug("Preparing to send alert email from=%s to=%s", emailFrom, emailRecipients);

        try {
            SimpleMailMessage msg = new SimpleMailMessage();
            msg.setFrom(emailFrom);
            msg.setTo(recipients.toArray(new String[0]));
            msg.setSubject(subject);
            msg.setText(body);

            mailSender.send(msg);
            logger.info("Alert email sent to %d recipients", recipients.size());
            return true;
        } catch (MailException mex) {
            logger.error("Failed to send alert email: {}", mex.getMessage(), mex);
            return false;
        } catch (Exception e) {
            logger.error("Unexpected error while sending alert email: {}", e.getMessage(), e);
            return false;
        }
    }

    // TODO: Add Slack, PagerDuty integrations
    public void sendSlackAlert(String message) {
        logger.debug("sendSlackAlert called (not yet implemented): %s", message);
    }

    public void sendPagerDutyAlert(String message) {
        logger.debug("sendPagerDutyAlert called (not yet implemented): %s", message);
    }
}
