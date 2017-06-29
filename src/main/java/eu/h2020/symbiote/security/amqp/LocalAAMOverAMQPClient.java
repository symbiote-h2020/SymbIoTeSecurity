package eu.h2020.symbiote.security.amqp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.RpcClient;
import eu.h2020.symbiote.security.constants.AAMConstants;
import eu.h2020.symbiote.security.enums.ValidationStatus;
import eu.h2020.symbiote.security.exceptions.custom.SecurityHandlerException;
import eu.h2020.symbiote.security.payloads.Credentials;
import eu.h2020.symbiote.security.payloads.ErrorResponseContainer;
import eu.h2020.symbiote.security.payloads.ValidationRequest;
import eu.h2020.symbiote.security.token.Token;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;

/**
 * Client used to access local/intenal AAM over AMQP by Symbiote components
 * <p>
 * TODO R3 rework to use Spring AMQP instead of rabbitMQ implementations
 *
 * @author Mikołaj Dobski (PSNC)
 */
public class LocalAAMOverAMQPClient {
    private static Log log = LogFactory.getLog(LocalAAMOverAMQPClient.class);

    private final ConnectionFactory factory = new ConnectionFactory();
    private final ObjectMapper mapper = new ObjectMapper();

    public LocalAAMOverAMQPClient(String rabbitMQHostIP, String rabbitMQUsername, String rabbitMQPassword) {
        factory.setHost(rabbitMQHostIP);
        factory.setUsername(rabbitMQUsername);
        factory.setPassword(rabbitMQPassword);
    }

    public Token login(Credentials credentials) throws SecurityHandlerException {
        byte[] response;
        // requesting login
        try {
            log.debug("Sending request of login for " + credentials.getUsername());

            RpcClient client = new RpcClient(factory.newConnection().createChannel(), "", AAMConstants
                    .AAM_LOGIN_QUEUE, 5000);

            response = client.primitiveCall(mapper.writeValueAsString(credentials)
                    .getBytes());
        } catch (Exception e) {
            log.error(e);
            throw new SecurityHandlerException(e.getMessage(), e);
        }
        // unpacking response
        try {
            // valid response
            return mapper.readValue(response, Token.class);
        } catch (IOException e) {
            try {
                // unpacking packed exception response
                ErrorResponseContainer errorResponseContainer = mapper.readValue(response, ErrorResponseContainer
                        .class);
                log.error(errorResponseContainer.getErrorMessage());
                throw new SecurityHandlerException(errorResponseContainer.getErrorMessage());
            } catch (IOException e1) {
                log.error(e1);
                throw new SecurityHandlerException("Error unpacking login response", e1);
            }
        }
    }

    public ValidationStatus validate(Token token) throws SecurityHandlerException {
        try {
            RpcClient client = new RpcClient(factory.newConnection().createChannel(), "", AAMConstants
                    .AAM_VALIDATE_QUEUE, 5000);
            byte[] amqpResponse = client.primitiveCall(mapper.writeValueAsString(new ValidationRequest(token.getToken(), "")).getBytes());

            return mapper.readValue(amqpResponse,
                    ValidationStatus.class);
        } catch (Exception e) {
            log.error(e);
            throw new SecurityHandlerException(e.getMessage(), e);
        }
    }
}
