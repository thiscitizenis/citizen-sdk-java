package is.citizen.sdk.util;

import com.neovisionaries.ws.client.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class WebStompClient extends WebSocketAdapter {

    public interface WebStompListener {
        void webStompStateChanged(String state, String message, String errorMessage);
    }

    public interface LoggingCallback {
        void webStompLoggingCallback(int code, String logMessage);
    }

    public enum WEBSTOMPSTATE {
        UNINITIALISED,
        WEB_SOCKET_CONNECTED,
        STOMP_CONNECTED,
        MESSAGE_WAIT,
        MESSAGE_RECEIVED,
        FINISHED,
        ERROR
    }

    private WEBSTOMPSTATE state = WEBSTOMPSTATE.UNINITIALISED;

    private boolean debug = false;

    private String remoteHost = "api.citizen.is";
    private int remotePort = 443;
    private boolean connectionSecure = true;

    private int connectionTimeout = 30000;

    private String webSocketEndpoint;
    private String stompSendEndpoint;
    private String stompSubscriptionEndpoint;

    private WebSocket socket = null;

    private String messageToSend;
    private String messageReceived = null;

    private String stompSubscriptionId;

    private String errorMessage = null;

    private List<WebStompListener> listeners = new ArrayList<WebStompListener>();
    private List<LoggingCallback> loggingCallbacks = new ArrayList<LoggingCallback>();

    public void sendStompMessageAndAwaitResponse() {

        String url;
        if (connectionSecure) {
            url = "wss://";
        } else {
            url = "ws://";
        }
        url = url + remoteHost + ":" + Integer.toString(remotePort) + webSocketEndpoint;

        if (debug) {
            log(Constant.CITIZEN_STOMP_INFO, "WebStomp: Connecting to: " + url);
        }

        try {
            socket = new WebSocketFactory()
                    .setConnectionTimeout(connectionTimeout)
                    .createSocket(url)
                    .addListener(this)
                    .connect();

        } catch (IOException | WebSocketException e) {
            errorMessage = e.getMessage();
            updateState(WEBSTOMPSTATE.ERROR);
        }
    }

    private void handleStompMessage(String message) {
        if (debug) {
            log(Constant.CITIZEN_STOMP_INFO, "RECV: " + message);
        }

        String messageParts[] = message.split("\n\n");

        if (messageParts.length < 1) {
            updateState(WEBSTOMPSTATE.ERROR);
            return;
        }

        String header = removeControlChars(messageParts[0]);

        if (header.matches("^CONNECTED.*")) {
            updateState(WEBSTOMPSTATE.STOMP_CONNECTED);

        } else if (header.matches("^MESSAGE.*")) {
            if (messageParts.length == 2) {
                messageReceived = removeControlChars(messageParts[1]);
                updateState(WEBSTOMPSTATE.MESSAGE_RECEIVED);
            } else {
                errorMessage = "Unable to parse message";
                updateState(WEBSTOMPSTATE.ERROR);
            }

        } else if (header.matches("^ERROR.*")) {
            errorMessage = removeControlChars(message);
            updateState(WEBSTOMPSTATE.ERROR);

        } else {
            errorMessage = "Unable to handle message: " + removeControlChars(message);
            updateState(WEBSTOMPSTATE.ERROR);
        }
    }

    @Override
    public void onConnected(WebSocket ws, Map<String, List<String>> headers) {
        updateState(WEBSTOMPSTATE.WEB_SOCKET_CONNECTED);

        if (debug) {
            log(Constant.CITIZEN_STOMP_INFO, "WebStomp: socket connected");
        }

        stompConnect();
    }

    @Override
    public void onTextMessage(WebSocket ws, String message) {

        handleStompMessage(message);

        if (state == WEBSTOMPSTATE.STOMP_CONNECTED) {
            stompSubscribe(stompSubscriptionEndpoint, stompSubscriptionId);
            stompSend(stompSendEndpoint, messageToSend, "text/plain");
            updateState(WEBSTOMPSTATE.MESSAGE_WAIT);

            if (debug) {
                log(Constant.CITIZEN_STOMP_INFO, "WebStomp: STOMP connected");
            }

        } else if (state == WEBSTOMPSTATE.MESSAGE_RECEIVED) {
            stompUnsubscribe(stompSubscriptionId);
            stompDisconnect();
            ws.disconnect();
            updateState(WEBSTOMPSTATE.FINISHED);

            if (debug) {
                log(Constant.CITIZEN_STOMP_INFO, "WebStomp: STOMP received message");
            }

        } else if (state != WEBSTOMPSTATE.ERROR) {
            errorMessage = "Cannot determine state";
            updateState(WEBSTOMPSTATE.ERROR);
            ws.disconnect();

            if (debug) {
                log(Constant.CITIZEN_STOMP_INFO, "WebStomp: STOMP error: cannot determine state");
            }

        } else {  // WEBSTOMPSTATE.ERROR.
            ws.disconnect();
        }
    }

    @Override
    public void onDisconnected(WebSocket websocket,
                               WebSocketFrame serverCloseFrame,
                               WebSocketFrame clientCloseFrame,
                               boolean closedByServer) {

        if (state != WEBSTOMPSTATE.FINISHED) {
            if (closedByServer) {
                errorMessage = "Closed by server";
            } else {
                errorMessage = "Closed by client";
            }
            updateState(WEBSTOMPSTATE.ERROR);
        }
    }

    private String removeControlChars(String data) {
        if (data != null) {
            return data.replaceAll("[^0-9A-Za-z{}\"\':,.=_\\-/+]", "");
        }

        return null;
    }

    private void updateState(WEBSTOMPSTATE newState) {
        state = newState;
        updateListeners();
    }

    private void closeWebSocket() {
        if (socket != null) {
            socket.disconnect();
        }
    }

    private void stompConnect() {
        String operation = "CONNECT";

        Map<String, String> headers = new HashMap<String, String>();
        headers.put("accept-version", "1.0,1.1");

        sendStompOperation(operation, headers, null);
    }

    private void stompSend(String destination, String data, String contentType) {
        String operation = "SEND";

        Map<String, String> headers = new HashMap<String, String>();
        headers.put("content-type", contentType);
        headers.put("destination", destination);

        sendStompOperation(operation, headers, data);
    }

    private void stompSubscribe(String destination, String subscriptionId) {
        String operation = "SUBSCRIBE";

        Map<String, String> headers = new HashMap<String, String>();
        headers.put("id", subscriptionId);
        headers.put("destination", destination);

        sendStompOperation(operation, headers, null);
    }

    private void stompUnsubscribe(String subscriptionId) {
        String operation = "UNSUBSCRIBE";

        Map<String, String> headers = new HashMap<String, String>();
        headers.put("id", subscriptionId);

        sendStompOperation(operation, headers, null);
    }

    private void stompDisconnect() {
        String operation = "DISCONNECT";

        sendStompOperation(operation, null, null);
    }

    private void sendStompOperation(String operation, Map<String, String> headers, String data) {
        String message = operation + "\r\n";

        if (headers != null) {
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                message += entry.getKey() + ":" + entry.getValue() + "\r\n";
            }
        }

        message += "\r\n";

        if (data != null) {
            message += data;
        }

        if (debug) {
            log(Constant.CITIZEN_STOMP_INFO, "SEND: " + message);
        }

        message += "\0";

        socket.sendText(message);
    }

    private void updateListeners() {
        for (WebStompListener listener : listeners) {
            listener.webStompStateChanged(state.toString(), messageReceived, errorMessage);
        }
    }

    public void addListener(WebStompListener listener) {
        listeners.add(listener);
    }

    public void registerLoggingCallback(LoggingCallback callback) {
        loggingCallbacks.add(callback);
    }

    private void log(int status, String logMessage) {
        for (LoggingCallback loggingCallback : loggingCallbacks) {
            loggingCallback.webStompLoggingCallback(status, logMessage);
        }
    }

    public void setStompParametersForApiKeyFromNonce(String nonce) {
        webSocketEndpoint = "/webapp/tokenLoginSock/websocket";
        stompSendEndpoint = "/webapp/tokenLogin/request/" + nonce;
        stompSubscriptionEndpoint = "/tokenLogin/response/" + nonce;
        messageToSend = "dummyText";
        stompSubscriptionId = "101";
    }

    public void setStompParametersForJwtFromNonce(String nonce) {
        webSocketEndpoint = "/webapp/tokenLoginSock/websocket";
        stompSendEndpoint = "/webapp/tokenLogin/thirdPartyJwtRequest/" + nonce;
        stompSubscriptionEndpoint = "/tokenLogin/thirdPartyJwtResponse/" + nonce;
        messageToSend = "dummyText";
        stompSubscriptionId = "101";
    }

    public boolean getDebug() {
        return debug;
    }

    public void setDebug(boolean debug) {
        this.debug = debug;
    }

    public void setRemoteHost(String remoteHost) {
        this.remoteHost = remoteHost;
    }

    public int getRemotePort() {
        return remotePort;
    }

    public void setRemotePort(int remotePort) {
        this.remotePort = remotePort;
    }

    public boolean getConnectionSecure() {
        return connectionSecure;
    }

    public void setConnectionSecure(boolean connectionSecure) {
        this.connectionSecure = connectionSecure;
    }

    public int getConnectionTimeout() {
        return connectionTimeout;
    }

    public void setConnectionTimeout(int connectionTimeout) {
        this.connectionTimeout = connectionTimeout;
    }

    public String getWebSocketEndpoint() {
        return webSocketEndpoint;
    }

    public void setWebSocketEndpoint(String webSocketEndpoint) {
        this.webSocketEndpoint = webSocketEndpoint;
    }

    public String getStompSendEndpoint() {
        return stompSendEndpoint;
    }

    public void setStompSendEndpoint(String stompSendEndpoint) {
        this.stompSendEndpoint = stompSendEndpoint;
    }

    public String getStompSubscriptionEndpoint() {
        return stompSubscriptionEndpoint;
    }

    public void setStompSubscriptionEndpoint(String stompSubscriptionEndpoint) {
        this.stompSubscriptionEndpoint = stompSubscriptionEndpoint;
    }

    public String getMessageToSend() {
        return messageToSend;
    }

    public void setMessageToSend(String messageToSend) {
        this.messageToSend = messageToSend;
    }

    public String getMessageReceived() {
        return messageReceived;
    }

    public String getStompSubscriptionId() {
        return stompSubscriptionId;
    }

    public void setStompSubscriptionId(String stompSubscriptionId) {
        this.stompSubscriptionId = stompSubscriptionId;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public String getState() {
        return state.toString();
    }
}
