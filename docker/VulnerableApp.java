import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

/**
 * VulnerableApp.java
 * A minimal HTTP server that logs User-Agent and X-Api-Version headers
 * using Log4j 2.14.1 — deliberately vulnerable to CVE-2021-44228 (Log4Shell).
 *
 * Academic use only — Akdeniz University CSE 472 Security Project.
 */
public class VulnerableApp {

    private static final Logger logger = LogManager.getLogger(VulnerableApp.class);

    public static void main(String[] args) throws IOException {
        int port = 8080;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new RootHandler());
        server.setExecutor(null);
        System.out.println("[VulnerableApp] Listening on port " + port);
        logger.info("VulnerableApp started on port {}", port);
        server.start();
    }

    static class RootHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // ---- Log4Shell entry points ----
            String userAgent = exchange.getRequestHeaders().getFirst("User-Agent");
            String apiVersion = exchange.getRequestHeaders().getFirst("X-Api-Version");
            String xForwardedFor = exchange.getRequestHeaders().getFirst("X-Forwarded-For");

            // These log calls are the vulnerable sinks
            logger.info("Request from User-Agent: {}", userAgent);
            logger.info("API Version header: {}", apiVersion);
            logger.info("X-Forwarded-For: {}", xForwardedFor);
            logger.info("URI: {}", exchange.getRequestURI().toString());

            String response = "{\"status\": \"ok\", \"message\": \"Request received\"}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(response.getBytes());
            }
        }
    }
}
