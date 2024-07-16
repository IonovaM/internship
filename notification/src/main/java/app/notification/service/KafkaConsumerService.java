package app.notification.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.support.Acknowledgment;
import org.springframework.stereotype.Service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class KafkaConsumerService {

    @Autowired
    private EmailService emailService;

    private static final Pattern MESSAGE_PATTERN = Pattern.compile("User registered: (.+?) \\(Email: (.+?)\\). Confirm account: (.+)");

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

            // Подтверждаем получение сообщения
            ack.acknowledge();
        } else {
            System.err.println("Message format is incorrect: " + message);
        }
    }
}
