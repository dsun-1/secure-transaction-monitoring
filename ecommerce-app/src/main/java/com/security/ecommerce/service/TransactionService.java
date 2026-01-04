package com.security.ecommerce.service;

import com.security.ecommerce.model.Transaction;
import com.security.ecommerce.model.User;
import com.security.ecommerce.repository.TransactionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
public class TransactionService {
    
    private static final Logger logger = LoggerFactory.getLogger(TransactionService.class);
    
    @Autowired
    private TransactionRepository transactionRepository;
    
    @Autowired
    private SecurityEventService securityEventService;
    
    public Transaction createTransaction(User user, BigDecimal amount, String lastFourDigits, String shippingAddress) {
        Transaction transaction = new Transaction();
        transaction.setTransactionId(UUID.randomUUID().toString());
        transaction.setUser(user);
        transaction.setAmount(amount);
        transaction.setOriginalAmount(amount);
        transaction.setPaymentMethod("CARD_" + lastFourDigits);
        transaction.setStatus(Transaction.TransactionStatus.COMPLETED);
        transaction.setTransactionDate(LocalDateTime.now());
        
        
        String username = user != null ? user.getUsername() : "guest";
        if (amount.compareTo(BigDecimal.ZERO) < 0) {
            transaction.setStatus(Transaction.TransactionStatus.FAILED);
            transaction.setFailureReason("Negative amount not allowed");
            securityEventService.logHighSeverityEvent(
                "TRANSACTION_ANOMALY",
                username,
                "Negative transaction amount attempted",
                "Amount: " + amount
            );
        } else if (amount.compareTo(new BigDecimal("10000")) > 0) {
            transaction.setStatus(Transaction.TransactionStatus.FAILED);
            transaction.setFailureReason("Amount exceeds limit");
            securityEventService.logHighSeverityEvent(
                "TRANSACTION_ANOMALY",
                username,
                "Suspiciously high transaction amount",
                "Amount: " + amount
            );
        }
        
        Transaction saved = transactionRepository.save(transaction);
        logger.info("Transaction created: {} - ${} - {}", transaction.getTransactionId(), amount, transaction.getStatus());
        
        return saved;
    }
    
    public Transaction createTransaction(String username, String transactionId, 
                                         double amount, String paymentMethod) {
        Transaction transaction = new Transaction();
        transaction.setTransactionId(transactionId);
        transaction.setAmount(BigDecimal.valueOf(amount));
        transaction.setOriginalAmount(BigDecimal.valueOf(amount));
        transaction.setPaymentMethod(paymentMethod);
        transaction.setStatus(Transaction.TransactionStatus.PENDING);
        transaction.setTransactionDate(LocalDateTime.now());
        
        
        if (amount < 0) {
            transaction.setStatus(Transaction.TransactionStatus.FAILED);
            transaction.setFailureReason("Negative amount not allowed");
            securityEventService.logHighSeverityEvent(
                "TRANSACTION_ANOMALY",
                username,
                "Negative transaction amount attempted",
                "Amount: " + amount
            );
        } else if (amount > 10000) {
            transaction.setStatus(Transaction.TransactionStatus.FAILED);
            transaction.setFailureReason("Amount exceeds limit");
            securityEventService.logHighSeverityEvent(
                "TRANSACTION_ANOMALY",
                username,
                "Suspiciously high transaction amount",
                "Amount: " + amount
            );
        }
        
        Transaction saved = transactionRepository.save(transaction);
        logger.info("Transaction created: {} - ${} - {}", transactionId, amount, transaction.getStatus());
        
        return saved;
    }
    
    public Transaction processTransaction(Long transactionId, boolean success, String failureReason) {
        Transaction transaction = transactionRepository.findById(transactionId)
            .orElseThrow(() -> new RuntimeException("Transaction not found"));
        
        transaction.setStatus(success ? Transaction.TransactionStatus.COMPLETED : 
                                       Transaction.TransactionStatus.FAILED);
        if (!success) {
            transaction.setFailureReason(failureReason);
        }
        
        return transactionRepository.save(transaction);
    }
    
    public List<Transaction> getAnomalousTransactions() {
        return transactionRepository.findAnomalousTransactions();
    }
    
    public List<Transaction> getRecentFailedTransactions(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return transactionRepository.findRecentFailedTransactions(since);
    }
}
