package is.citizen.sdk.util;

import is.citizen.sdk.exception.RestException;

import com.fasterxml.jackson.databind.DeserializationFeature;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.client.RestClientException;

import java.util.ArrayList;
import java.util.List;


public class RestClient {
    public String apiHost = Constant.CITIZEN_PRODUCTION_API_HOST;
    public int apiPort = Constant.CITIZEN_PRODUCTION_API_PORT;
    public boolean apiSecure = Constant.CITIZEN_PRODUCTION_API_SECURE;

    public String BaseUrl;

    private static RestClient instance;

    private RestTemplate restTemplate;

    private String apiKey;
    private String secret;
    private String signature;

    public RestClient() {
        // This is added as a workaround to a Java bug with HTTP PATCH requests.
        HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
        requestFactory.setConnectTimeout(30000);
        requestFactory.setReadTimeout(30000);
        restTemplate = new RestTemplate();
        MappingJackson2HttpMessageConverter messageConverter = new MappingJackson2HttpMessageConverter();
        messageConverter.getObjectMapper().disable(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES);
        restTemplate.getMessageConverters().add(messageConverter);
        restTemplate.setRequestFactory(requestFactory);

        BaseUrl = "";

        if (apiSecure) {
            BaseUrl = "https://";
        } else {
            BaseUrl = "http://";
        }

        BaseUrl += apiHost + ":" + apiPort + "/";
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }

    public static RestClient getInstance() {
        if (instance == null) {
            instance = new RestClient();
        }

        return instance;
    }

    public <T> T getUrl(String url, final Class<T> responseType) {
        HttpHeaders httpHeaders = createBasicHeaders();
        HttpEntity<Object> httpEntity = new HttpEntity<>(null, httpHeaders);
        T body = getRestTemplate().exchange(url, HttpMethod.GET, httpEntity, responseType).getBody();
        return body;
    }


    public <T> T get(String resourcePath, final Class<T> responseType)
        throws RestException {
        HttpHeaders httpHeaders = createBasicHeaders();
        setApiHeaders(httpHeaders);
        HttpEntity<Object> httpEntity = new HttpEntity<>(null, httpHeaders);

        try {
           ResponseEntity<T> response = getRestTemplate().exchange(BaseUrl + resourcePath, HttpMethod.GET, httpEntity, responseType);

           return response.getBody();
        } catch (RestClientException e) {
            throw new RestException(e.getMessage());
        }
    }

    public <T> T post(String resourcePath, Object requestBody, final Class<T> responseType)
        throws RestException {

        HttpHeaders httpHeaders = createBasicHeaders();
        setApiHeaders(httpHeaders);
        HttpEntity<Object> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

        try {
           ResponseEntity<T> response = getRestTemplate().exchange(BaseUrl + resourcePath, HttpMethod.POST, httpEntity, responseType);
           return response.getBody();
        } catch (RestClientException e) {
           throw new RestException(e.getMessage());
        }
    }

    public <T> T patch(String resourcePath, Object requestBody, final Class<T> responseType)
        throws RestException {
        HttpHeaders httpHeaders = createBasicHeaders();
        setApiHeaders(httpHeaders);
        HttpEntity<Object> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

        try {
           ResponseEntity<T> response = getRestTemplate().exchange(BaseUrl + resourcePath, HttpMethod.PATCH, httpEntity, responseType);
           return response.getBody();
        } catch (RestClientException e) {
           throw new RestException(e.getMessage());
        }
    }

    public <T> T put(String resourcePath, Object requestBody, final Class<T> responseType)
        throws RestException {
        HttpHeaders httpHeaders = createBasicHeaders();
        setApiHeaders(httpHeaders);
        HttpEntity<Object> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

        try {
           ResponseEntity<T> response = getRestTemplate().exchange(BaseUrl + resourcePath, HttpMethod.PUT, httpEntity, responseType);

           return response.getBody();
        } catch (RestClientException e) {
            throw new RestException(e.getMessage());
        }
    }

    public <T> T delete(String resourcePath, Object requestBody, final Class<T> responseType)
        throws RestException {
        HttpHeaders httpHeaders = createBasicHeaders();
        setApiHeaders(httpHeaders);
        HttpEntity<Object> httpEntity = new HttpEntity<>(requestBody, httpHeaders);

        try {
           ResponseEntity<T> response = getRestTemplate().exchange(BaseUrl + resourcePath, HttpMethod.DELETE, httpEntity, responseType);

           return response.getBody();
        } catch (RestClientException e) {
            throw new RestException(e.getMessage());
        }
    }


    private HttpHeaders createBasicHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();

        List<MediaType> mediaTypeList = new ArrayList<>();
        mediaTypeList.add((MediaType.APPLICATION_JSON));
        httpHeaders.setAccept(mediaTypeList);
        httpHeaders.setContentType(MediaType.APPLICATION_JSON);
        httpHeaders.set(HttpHeaders.CONNECTION, "Close");

        return httpHeaders;
    }

    private void setApiHeaders(HttpHeaders httpHeaders) {
        if (apiKey != null) {
            httpHeaders.add(Constant.CITIZEN_AUTHORISATION_HEADER_NAME, apiKey);
        }

        if (secret != null) {
            httpHeaders.add(Constant.CITIZEN_SECRET_HEADER_NAME, secret);
        }

        if (signature != null) {
            httpHeaders.add(Constant.CITIZEN_SIGNATURE_HEADER_NAME, signature);
        }
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public void clearApiHeaders() {
        apiKey = null;
        secret = null;
        signature = null;
    }

    public void setApiHost(String apiHost) {
        BaseUrl = "";

        if (apiSecure) {
            BaseUrl = "https://";
        } else {
            BaseUrl = "http://";
        }

        BaseUrl += apiHost + ":" + apiPort + "/";

        this.apiHost = apiHost;
    }

    public void setApiPort(int apiPort) {
        BaseUrl = "";

        if (apiSecure) {
            BaseUrl = "https://";
        } else {
            BaseUrl = "http://";
        }

        BaseUrl += apiHost + ":" + apiPort + "/";

        this.apiPort = apiPort;
    }

    public void setApiSecure(boolean apiSecure) {
        BaseUrl = "";

        if (apiSecure) {
            BaseUrl = "https://";
        } else {
            BaseUrl = "http://";
        }

        BaseUrl += apiHost + ":" + apiPort + "/";

        this.apiSecure = apiSecure;
    }
}
