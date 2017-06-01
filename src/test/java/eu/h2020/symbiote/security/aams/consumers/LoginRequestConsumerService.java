package eu.h2020.symbiote.security.aams.consumers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;
import eu.h2020.symbiote.security.enums.IssuingAuthorityType;
import eu.h2020.symbiote.security.exceptions.custom.JWTCreationException;
import eu.h2020.symbiote.security.exceptions.custom.ValidationException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.token.Token;
import eu.h2020.symbiote.security.token.jwt.JWTEngine;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;

/**
 * RabbitMQ Consumer implementation used for Login actions
 */
public class LoginRequestConsumerService extends DefaultConsumer {

    private static Log log = LogFactory.getLog(LoginRequestConsumerService.class);


    /**
     * Constructs a new instance and records its association to the passed-in channel.
     * Managers beans passed as parameters because of lack of possibility to inject it to consumer.
     *
     * @param channel the channel to which this consumer is attached
     */
    public LoginRequestConsumerService(Channel channel) {
        super(channel);
    }

    /**
     * Called when a <code><b>basic.deliver</b></code> is received for this consumer.
     *
     * @param consumerTag the <i>consumer tag</i> associated with the consumer
     * @param envelope    packaging data for the message
     * @param properties  content header data for the message
     * @param body        the message body (opaque, client-specific byte array)
     * @throws IOException if the consumer encounters an I/O error while processing the message
     * @see Envelope
     */
    @Override
    public void handleDelivery(String consumerTag, Envelope envelope,
                               AMQP.BasicProperties properties, byte[] body)
            throws IOException {

        String message = new String(body, "UTF-8");
        ObjectMapper om = new ObjectMapper();
        Credentials loginReq;
        String response;

        log.debug("[x] Received Login Request: '" + message + "'");

        if (properties.getReplyTo() != null || properties.getCorrelationId() != null) {

            AMQP.BasicProperties replyProps = new AMQP.BasicProperties
                    .Builder()
                    .correlationId(properties.getCorrelationId())
                    .build();
            try {
                loginReq = om.readValue(message, Credentials.class);

                try {

                    log.info("User trying to login " + loginReq.getUsername() + " - " + loginReq.getPassword());

                    final String ALIAS = "test aam keystore";
                    KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
                    ks.load(new FileInputStream("./src/test/resources/TestAAM.keystore"), "1234567".toCharArray());
                    Key key = ks.getKey(ALIAS, "1234567".toCharArray());

                    HashMap<String, String> attributes = new HashMap<>();
                    attributes.put("name", "test2");
                    String tokenString = JWTEngine.generateJWTToken(loginReq.getUsername(), attributes, ks
                                    .getCertificate(ALIAS).getPublicKey().getEncoded(), IssuingAuthorityType.PLATFORM,
                            DateUtil.addDays(new Date(), 1).getTime(),
                            "securityHandlerTestPlatformAAM", ks.getCertificate(ALIAS).getPublicKey(), (PrivateKey)
                                    key);

                    response = om.writeValueAsString(new Token(tokenString));
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                } catch (JWTCreationException | ValidationException e) {
                    log.error(e);
                    response = (new ErrorResponseContainer(e.getErrorMessage(), e.getStatusCode().ordinal())).toJson();
                    this.getChannel().basicPublish("", properties.getReplyTo(), replyProps, response.getBytes());
                } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException |
                        UnrecoverableKeyException | KeyStoreException e) {
                    log.error(e);
                }

            } catch (IOException e) {
                log.error(e);
                throw e;
            }

            log.info("Login Response: sent back");
        } else {
            log.warn("Received RPC message without ReplyTo or CorrelationId properties.");
        }
        this.getChannel().basicAck(envelope.getDeliveryTag(), false);
    }

    static public class DateUtil {
        public static Date addDays(Date date, int days) {
            Calendar cal = Calendar.getInstance();
            cal.setTime(date);
            cal.add(Calendar.DATE, days); //minus number would decrement the days
            return cal.getTime();
        }
    }
}