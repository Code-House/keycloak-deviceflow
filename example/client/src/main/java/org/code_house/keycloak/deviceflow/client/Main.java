package org.code_house.keycloak.deviceflow.client;

import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationRequest;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationRequest.Builder;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationResponse;
import com.nimbusds.oauth2.sdk.device.DeviceAuthorizationSuccessResponse;
import com.nimbusds.oauth2.sdk.device.DeviceCodeGrant;
import com.nimbusds.oauth2.sdk.device.UserCode;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import java.net.URI;
import java.time.Clock;
import java.util.Date;
import java.util.concurrent.TimeUnit;

public class Main {

  public static void main(String[] args) throws Exception {
    String uri = "http://id.connectorio.com:8080/realms/device/";
    URI deviceAuthURI = new URI(uri + "protocol/openid-connect/auth/device");
    URI tokenURI = new URI(uri + "protocol/openid-connect/token");
    ClientID clientID = new ClientID("mydevice");
    Secret secret = new Secret("7r1HHmyDJsUt72EY6qODiZ5rvQHa2cz7");
    Scope scope = new Scope("openid", "profile");

    DeviceAuthorizationRequest authorizationRequest = new Builder(new ClientSecretBasic(clientID, secret))
        .scope(scope)
        .endpointURI(deviceAuthURI)
        .build();
    HTTPRequest httpRequest = authorizationRequest.toHTTPRequest();
    httpRequest.setHeader("Accept", "application/json");
    HTTPResponse httpResponse = httpRequest.send();

    DeviceAuthorizationResponse response = DeviceAuthorizationResponse.parse(httpResponse);
    if (!response.indicatesSuccess()) {
      DeviceAuthorizationErrorResponse errorResponse = response.toErrorResponse();
      throw new RuntimeException("Could not finish request. Server returned "
          + " HTTP status code " + errorResponse.getErrorObject().getHTTPStatusCode()
          + " error code " + errorResponse.getErrorObject().getCode()
          + " error description " + errorResponse.getErrorObject().getDescription());
    }

    long now = Clock.systemUTC().millis();
    DeviceAuthorizationSuccessResponse successResponse = response.toSuccessResponse();
    long maxLifetime = TimeUnit.SECONDS.toMillis(successResponse.getLifetime()) + now;

    System.out.println("Received code response");
    System.out.println("Your user code: " + successResponse.getUserCode());
    System.out.println("Valid to: " + new Date(maxLifetime));
    System.out.println("Please enter code in page: " + successResponse.getVerificationURI());
    System.out.println("Or confirm linking: " + successResponse.getVerificationURIComplete());

    DeviceCodeGrant grant = new DeviceCodeGrant(successResponse.getDeviceCode());
    TokenRequest request = new TokenRequest(tokenURI, new ClientSecretBasic(clientID, secret),
        grant, scope, null, null);

    new Thread(() -> requestToken(maxLifetime, request, successResponse.getUserCode()), "requester").start();
    System.in.read();
  }

  private static void requestToken(long maxLifetime, TokenRequest tokenRequest, UserCode userCode) {
    while (Clock.systemUTC().millis() < maxLifetime) {
      try {
        final HTTPRequest httpRequest = tokenRequest.toHTTPRequest();
        HTTPResponse httpResponse = httpRequest.send();

        if (httpResponse.getStatusCode() == 400) {
          System.out.println("User did not complete operation with code " + userCode);
          System.out.println(httpResponse.getContent());
        } else if (httpResponse.indicatesSuccess()) {
          System.out.println("User completed authentication with " + userCode);
          OIDCTokenResponse tokenResponse = OIDCTokenResponse.parse(httpResponse);
          AccessToken accessToken = tokenResponse.getTokens().getAccessToken();
          RefreshToken refreshToken = tokenResponse.getTokens().getRefreshToken();
          JWT idToken = tokenResponse.getOIDCTokens().getIDToken();
          System.out.println("Access token: " + accessToken);
          System.out.println("Refresh token: " + refreshToken);
          System.out.println("ID token: " + idToken);
          break;
        }
        sleep();
      } catch (Exception e) {
        System.out.println("Could not retrieve token " + e);
      }
    }
  }

  private static void sleep() throws InterruptedException {
    Thread.sleep(30_00);
  }

}
