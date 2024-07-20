package app.notification.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;
import app.notification.service.EmailService;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class NotificationController {

    @Autowired
    private EmailService emailService;

    private static final Pattern MESSAGE_PATTERN = Pattern.compile("User registered: (.+?) \\(Email: (.+?)\\). Confirm account: (.+)");
    private static final Pattern PASSWORD_RESET_MESSAGE_PATTERN = Pattern.compile("Password reset requested: (.+?) \\(Email: (.+?)\\). Reset link: (.+)");
    private static final Pattern ACCOUNT_DELETION_MESSAGE_PATTERN = Pattern.compile("User account deleted: (.+?) \\(Email: (.+?)\\)");

    @KafkaListener(topics = "user-registration-topic", groupId = "email-group")
    public void listen(String message, Acknowledgment ack) {
        System.out.println("Received message: " + message);

        Matcher matcher = MESSAGE_PATTERN.matcher(message);
        if (matcher.matches()) {
            String username = matcher.group(1);
            String email = matcher.group(2);
            String confirmUrl = matcher.group(3);

            String subject = "Welcome to Our Service!";
            String text = "Dear " + username + ",\n\nThank you for registering with our service!\nPlease confirm your account by clicking the following link: " + confirmUrl;

            emailService.sendSimpleMessage(email, subject, text);

            ack.acknowledge();
        } else {
            System.err.println("Message format is incorrect: " + message);
        }
    }

    @KafkaListener(topics = "password-reset-topic", groupId = "email-group")
    public void listenPasswordReset(String message, Acknowledgment ack) {
        System.out.println("Received password reset message: " + message);

        Matcher matcher = PASSWORD_RESET_MESSAGE_PATTERN.matcher(message);
        if (matcher.matches()) {
            String username = matcher.group(1);
            String email = matcher.group(2);
            String resetUrl = matcher.group(3);

            String subject = "Password Reset Request";
            String text = "Dear " + username + ",\n\nWe received a request to reset your password.\nPlease reset your password by clicking the following link: " + resetUrl;

            emailService.sendSimpleMessage(email, subject, text);

            ack.acknowledge();
        } else {
            System.err.println("Password reset message format is incorrect: " + message);
        }
    }

    @KafkaListener(topics = "account-deletion-topic", groupId = "email-group")
    public void listenAccountDeletion(String message, Acknowledgment ack) {
        System.out.println("Received account deletion message: " + message);

        Matcher matcher = ACCOUNT_DELETION_MESSAGE_PATTERN.matcher(message);
        if (matcher.matches()) {
            String username = matcher.group(1);
            String email = matcher.group(2);

            String subject = "Account Deleted";
            String text = "Dear " + username + ",\n\nYour account has been successfully deleted from our system.";

            emailService.sendSimpleMessage(email, subject, text);

            ack.acknowledge();
        } else {
            System.err.println("Account deletion message format is incorrect: " + message);
        }
    }
}
