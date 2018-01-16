package eu.h2020.symbiote.security.communication;

import java.io.IOException;

import org.apache.commons.logging.Log;

import feign.Request;
import feign.Response;

public class ApacheCommonsLogger4Feign extends feign.Logger {
    private Log logger;

    public ApacheCommonsLogger4Feign(Log logger) {
        this.logger = logger;
    }

    @Override
    protected void logRequest(String configKey, Level logLevel, Request request) {
      if (logger.isDebugEnabled()) {
        super.logRequest(configKey, logLevel, request);
      }
    }

    @Override
    protected Response logAndRebufferResponse(String configKey, Level logLevel, Response response,
                                              long elapsedTime) throws IOException {
      if (logger.isDebugEnabled()) {
        return super.logAndRebufferResponse(configKey, logLevel, response, elapsedTime);
      }
      return response;
    }

    @Override
    protected void log(String configKey, String format, Object... args) {
      if (logger.isDebugEnabled()) {
        logger.debug(String.format(methodTag(configKey) + format, args));
      }
    }
}
