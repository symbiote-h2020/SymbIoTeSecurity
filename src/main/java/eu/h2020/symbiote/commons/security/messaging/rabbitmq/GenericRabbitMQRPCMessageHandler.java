package eu.h2020.symbiote.commons.security.messaging.rabbitmq;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.fasterxml.jackson.databind.JavaType;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP.BasicProperties;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;


/**
 * This class is to communicate with RabbitMQ. Initially created by Elena
 *
 * @author: Elena Garrido
 * @version: 18/01/2017
 */
public class GenericRabbitMQRPCMessageHandler<T, O> {

    private static Log logger = LogFactory.getLog(GenericRabbitMQRPCMessageHandler.class);

    private String rabbitMQHostIP;
    private String exchangeName = "";
    private Connection connection;
    private Channel channel;
    private String replyQueueName;
    private String requestQueueName;
    private Type type;


    public GenericRabbitMQRPCMessageHandler(String rabbitMQHostIP, String exchangeName, String requestQueueName,
                                            String replyQueueName, Type type) {
        logger.info("Creating with requestQueueName:" + requestQueueName + " and replyQueueName:" + replyQueueName);
        this.replyQueueName = replyQueueName;
        this.requestQueueName = requestQueueName;
        this.exchangeName = exchangeName;
        this.rabbitMQHostIP = rabbitMQHostIP;
        this.type = type;

    }

    public void connect() throws Exception {
        ConnectionFactory factory = new ConnectionFactory();
        factory.setHost(rabbitMQHostIP);
        connection = factory.newConnection();
        channel = connection.createChannel();
        replyQueueName = channel.queueDeclare().getQueue();
    }

    /**
     * Method for sending a message to specified 'queue' on RabbitMQ server. Object is converted to Json.
     *
     * @param object
     * @throws Exception
     */
	public O sendMessage(T object) throws Exception {
        O result = null;
        
        String corrId = java.util.UUID.randomUUID().toString();

        ObjectMapper mapper = new ObjectMapper();
        String objectInJson = mapper.writeValueAsString(object);

        BasicProperties props = new BasicProperties
                .Builder()
                .correlationId(corrId)
                .contentType("application/json")
                .replyTo(replyQueueName)
                .build();

        channel.basicPublish(exchangeName, requestQueueName, props, objectInJson.getBytes());

        final BlockingQueue<String> response = new ArrayBlockingQueue<String>(1);

        channel.basicConsume(replyQueueName, true, new DefaultConsumer(channel) {
            @Override
            public void handleDelivery(String consumerTag, Envelope envelope, BasicProperties props, byte[] body)
                    throws IOException {
                if (props.getCorrelationId().equals(corrId)) {
                    response.offer(new String(body, "UTF-8"));
                }
            }
        });
        String answer = response.take();
        logger.info("Received reply: " + answer);
        JavaType javaType = mapper.getTypeFactory().constructType(type);
        result = mapper.readValue(answer, javaType);
        
        
        logger.info("Result " + result);
        return result;

    }

    public void close() throws Exception {
        connection.close();
    }

}

