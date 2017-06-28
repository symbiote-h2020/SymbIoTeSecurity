package eu.h2020.symbiote.security.aams;

import com.rabbitmq.client.*;
import eu.h2020.symbiote.security.aams.consumers.LoginRequestConsumerService;
import eu.h2020.symbiote.security.aams.consumers.ValidateRequestConsumerService;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.exceptions.custom.SecurityMisconfigurationException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.annotation.PreDestroy;
import java.io.IOException;
import java.util.concurrent.TimeoutException;

public class DummyAAMAMQPListener {

    private static Log log = LogFactory.getLog(DummyAAMAMQPListener.class);

    private Connection connection;

    /**
     * Initiates connection with Rabbit server using parameters from Bootstrap Properties
     *
     * @throws IOException
     * @throws TimeoutException
     */
    public Connection getConnection() throws IOException, TimeoutException {
        if (connection == null) {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setHost("localhost");
            factory.setUsername("guest");
            factory.setPassword("guest");
            this.connection = factory.newConnection();
        }
        return this.connection;
    }


    /**
     * Closes given channel if it exists and is open.
     *
     * @param channel rabbit channel to close
     */
    private void closeChannel(Channel channel) {
        try {
            if (channel != null && channel.isOpen())
                channel.close();
        } catch (IOException | TimeoutException e) {
            log.error(e);
        }
    }


    /**
     * Method gathers all of the rabbit consumer starter methods
     */
    private void startConsumers() throws SecurityMisconfigurationException {
        try {
            startConsumerOfValidateRequestMessages();
            startConsumerOfLoginRequestMessages();
        } catch (InterruptedException | IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Login requests.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void startConsumerOfLoginRequestMessages() throws InterruptedException, IOException {

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(AAMConstants.AAM_LOGIN_QUEUE, true, false, false, null);
            channel.queueBind(AAMConstants.AAM_LOGIN_QUEUE, AAMConstants
                    .AAM_EXCHANGE_NAME, AAMConstants.AAM_LOGIN_ROUTING_KEY);
            log.info("Authentication and Authorization Manager waiting for login request messages....");

            Consumer consumer = new LoginRequestConsumerService(channel);
            channel.basicConsume(AAMConstants.AAM_LOGIN_QUEUE, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }

    /**
     * Method creates queue and binds it globally available exchange and adequate Routing Key.
     * It also creates a consumer for messages incoming to this queue, regarding to Login requests.
     *
     * @throws InterruptedException
     * @throws IOException
     */
    private void startConsumerOfValidateRequestMessages() throws InterruptedException, IOException {

        String queueName = AAMConstants.AAM_VALIDATE_QUEUE;

        Channel channel;

        try {
            channel = this.connection.createChannel();
            channel.queueDeclare(queueName, true, false, false, null);
            channel.queueBind(queueName, AAMConstants
                    .AAM_EXCHANGE_NAME, AAMConstants.AAM_VALIDATE_ROUTING_KEY);

            log.info("Authentication and Authorization Manager waiting for check token revocation request messages");

            Consumer consumer = new ValidateRequestConsumerService(channel);
            channel.basicConsume(queueName, false, consumer);
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method creates channel and declares Rabbit exchanges for AAM features.
     * It triggers start of all consumers used in with AAM communication.
     */
    public void init() throws SecurityMisconfigurationException {
        Channel channel = null;

        try {
            getConnection();
        } catch (IOException | TimeoutException e) {
            log.error(e);
        }

        if (connection != null) {
            try {
                channel = this.connection.createChannel();

                channel.exchangeDeclare(AAMConstants.AAM_EXCHANGE_NAME,
                        "direct",
                        true,
                        false,
                        false,
                        null);

                startConsumers();

            } catch (IOException e) {
                log.error(e);
            } finally {
                closeChannel(channel);
            }
        }
    }


    @PreDestroy
    public void cleanup() {

        //FIXME check if there is better exception handling in @predestroy method
        log.info("Rabbit cleaned!");
        try {
            Channel channel;
            if (this.connection != null && this.connection.isOpen()) {
                channel = connection.createChannel();
                // check revocation
                channel.queueUnbind(AAMConstants.AAM_VALIDATE_QUEUE, AAMConstants.AAM_EXCHANGE_NAME,
                        AAMConstants.AAM_VALIDATE_ROUTING_KEY);
                channel.queueDelete(AAMConstants.AAM_VALIDATE_QUEUE);
                // login
                channel.queueUnbind(AAMConstants.AAM_LOGIN_QUEUE, AAMConstants
                                .AAM_EXCHANGE_NAME,
                        AAMConstants.AAM_LOGIN_ROUTING_KEY);
                channel.queueDelete(AAMConstants.AAM_LOGIN_QUEUE);

                closeChannel(channel);
                this.connection.close();
            }
        } catch (IOException e) {
            log.error(e);
        }
    }


    /**
     * Method publishes given message to the given exchange and routing key.
     * Props are set for correct message handle on the receiver side.
     *
     * @param exchange   name of the proper Rabbit exchange, adequate to topic of the communication
     * @param routingKey name of the proper Rabbit routing key, adequate to topic of the communication
     * @param message    message content in JSON String format
     */
    private void sendMessage(String exchange, String routingKey, String message) {
        AMQP.BasicProperties props;
        Channel channel = null;
        try {
            channel = this.connection.createChannel();
            props = new AMQP.BasicProperties()
                    .builder()
                    .contentType("application/json")
                    .build();

            channel.basicPublish(exchange, routingKey, props, message.getBytes());
        } catch (IOException e) {
            log.error(e);
        } finally {
            closeChannel(channel);
        }
    }
}
