//package com.zaidMEx.security.email;
//
//import lombok.AllArgsConstructor;
//import lombok.NoArgsConstructor;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.mail.javamail.JavaMailSender;
//import org.springframework.mail.javamail.JavaMailSenderImpl;
//import org.springframework.mail.javamail.MimeMessageHelper;
//import org.springframework.scheduling.annotation.Async;
//import org.springframework.stereotype.Service;
//
//import javax.mail.MessagingException;
//import javax.mail.internet.MimeMessage;
//import java.util.Properties;
//
//@Service
//@AllArgsConstructor
//
//public class EmailService implements EmailSender{
//
//    private final static Logger LOGGER = LoggerFactory
//            .getLogger(EmailService.class);
//
//    private final JavaMailSender mailSender;
//
//    @Override
//    @Async
//    public void send(String to, String email) {
//        try {
//            MimeMessage mimeMessage = mailSender.createMimeMessage();
//            MimeMessageHelper helper =
//                    new MimeMessageHelper(mimeMessage, "utf-8");
//            helper.setText(email, true);
//            helper.setTo(to);
//            helper.setSubject("Confirm your email");
//            helper.setFrom("zaidgabri976@gmail.com");
//            mailSender.send(mimeMessage);
//        } catch (MessagingException e) {
//            LOGGER.error("failed to send email", e);
//            throw new IllegalStateException("failed to send email");
//        }
//    }
//
//}
