package com.security.ecommerce.service;

import com.security.ecommerce.model.Transaction;
import com.security.ecommerce.model.User;
import com.security.ecommerce.repository.TransactionRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@Transactional
// transaction creation with anomaly logging
public class TransactionService {
    
    private static final Logger logger = LoggerFactory.getLogger(TransactionService.class);
    
    private final TransactionRepository transactionRepository;
    private final SecurityEventService securityEventService;

    public TransactionService(TransactionRepository transactionRepository,
                              SecurityEventService securityEventService) {
        this.transactionRepository = transactionRepository;
        this.securityEventService = securityEventService;
    }
    
    public Transaction createTransaction(User user, BigDecimal amount, String lastFourDigits) {
        Transaction transaction = new Transaction();
        transaction.setTransactionId(UUID.randomUUID().toString());
        transaction.setUser(user);
        transaction.setAmount(amount);
        transaction.setOriginalAmount(amount);
        transaction.setPaymentMethod("CARD_" + lastFourDigits);
        transaction.setStatus(Transaction.TransactionStatus.COMPLETED);
        transaction.setTransactionDate(LocalDateTime.now());
        
        // flag suspicious amounts before persistence
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
            securityEventService.recordTransactionAnomaly(
                transaction.getTransactionId(),
                username,
                "NEGATIVE_AMOUNT",
                amount.doubleValue(),
                amount.doubleValue(),
                "Negative transaction amount attempted"
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
            securityEventService.recordTransactionAnomaly(
                transaction.getTransactionId(),
                username,
                "HIGH_AMOUNT",
                amount.doubleValue(),
                amount.doubleValue(),
                "Suspiciously high transaction amount"
            );
        }
        
        Transaction saved = transactionRepository.save(transaction);
        logger.info("Transaction created: {} - ${} - {}", transaction.getTransactionId(), amount, transaction.getStatus());
        
        return saved;
    }
    
    public List<Transaction> getAnomalousTransactions() {
        return transactionRepository.findAnomalousTransactions();
    }

    public List<Transaction> getRecentFailedTransactions(int hours) {
        LocalDateTime since = LocalDateTime.now().minusHours(hours);
        return transactionRepository.findRecentFailedTransactions(since);
    }

    public List<Transaction> getAllTransactions() {
        return transactionRepository.findAll();
    }

    public Transaction getTransactionById(@NonNull Long id) {
        return transactionRepository.findById(id).orElse(null);
    }
}
