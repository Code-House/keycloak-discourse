/*
 *  Keycloak-Discourse Identity Provider
 *  Copyright (C) 2023, Code-House Łukasz Dywicki
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package org.code_house.keycloak.discourse.idp;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Hex;
import org.keycloak.broker.provider.AbstractIdentityProvider;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.FederatedIdentityModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main implementation of identity provider.
 */
public class DiscourseIdentityProvider extends AbstractIdentityProvider<DiscourseIdentityProviderConfig>
  implements SocialIdentityProvider<DiscourseIdentityProviderConfig> {

  public DiscourseIdentityProvider(KeycloakSession session, DiscourseIdentityProviderConfig config) {
    super(session, config);
  }

  @Override
  public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
    return new DiscourseIdentityProvider.Endpoint(session, realm, callback, event);
  }

  @Override
  public Response performLogin(AuthenticationRequest request) {
    try {
      String nonce = request.getState().getEncoded();
      String payload = "nonce=" + nonce + "&return_sso_url=" + request.getRedirectUri();
      String base64payload = new String(Base64.getEncoder().encode(payload.getBytes()));

      String hexSignature = hmac(base64payload, getConfig().getSsoSecret());
      String encodedPayload = URLEncoder.encode(base64payload, StandardCharsets.UTF_8);

      String address = getConfig().getDiscourseAddress();
      address += "/session/sso_provider?";
      address += "sso=" + encodedPayload;
      address += "&sig=" + hexSignature;
      URI authenticationUrl = URI.create(address);

      return Response.seeOther(authenticationUrl).build();
    } catch (Exception e) {
      throw new IdentityBrokerException("Could send authentication request to Discourse.", e);
    }
  }

  protected class Endpoint {
    protected RealmModel realm;
    protected AuthenticationCallback callback;
    protected EventBuilder event;

    @Context
    protected KeycloakSession session;

    @Context
    protected ClientConnection clientConnection;

    @Context
    protected HttpHeaders headers;

    public Endpoint(KeycloakSession session, RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
      this.session = session;
      this.realm = realm;
      this.callback = callback;
      this.event = event;
    }

    @GET
    public Response authResponse(@QueryParam("sso") String sso, @QueryParam("sig") String signature)
      throws Exception {
      Map<String, String> data = parse(getConfig().getSsoSecret(), sso, signature);
      String state = data.get("nonce");

      if (state == null) {
        return callback.error("Could not correlate request");
      }
      AuthenticationSessionModel authSession = callback.getAndVerifyAuthenticationSession(state);
      if (authSession == null) {
        return callback.error("Could not identify request");
      }

      try {
        BrokeredIdentityContext identity = new BrokeredIdentityContext(data.get("external_id"));
        identity.setAuthenticationSession(authSession);
        identity.setIdp(DiscourseIdentityProvider.this);
        identity.setUsername(data.get("username"));
        identity.setEmail(data.get("email"));
        identity.setUserAttribute("moderator", data.get("moderator"));
        identity.setUserAttribute("admin", data.get("admin"));
        identity.setIdpConfig(getConfig());
        return callback.authenticated(identity);
      } catch (Exception e) {
        return callback.error("Error while logging in via identity provider");
      }
    }
  }

  @Override
  public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
    return Response.ok(identity.getToken()).type(MediaType.APPLICATION_JSON).build();
  }

  @Override
  public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context) {
    authSession.setUserSessionNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, (String)context.getContextData().get(IdentityProvider.FEDERATED_ACCESS_TOKEN));

  }

  private static Map<String, String> parse(String key, String sso, String sig) throws Exception {
    String query = new String(Base64.getDecoder().decode(sso), StandardCharsets.UTF_8);
    String[] params = query.split("&");

    String signature = hmac(sso, key);
    if (!sig.equalsIgnoreCase(signature)) {
      throw new IllegalArgumentException("SSO payload was tampered");
    }

    Map<String, String> queryParams = new HashMap<>();
    for (String param : params) {
      String[] pair = param.split("=");
      if (pair.length > 1) {
        queryParams.put(pair[0], URLDecoder.decode(pair[1]));
      } else {
        queryParams.put(pair[0], "");
      }
    }

    return queryParams;
  }

  private static String hmac(String data, String key) throws NoSuchAlgorithmException, InvalidKeyException {
    SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes(), "HmacSHA256");
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(secretKeySpec);
    return Hex.encodeHexString(mac.doFinal(data.getBytes()));
  }

  private static final char[] hexchars = new char[]{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

  private static String toHex(byte[] buf) {
    return toHex(buf, 0, buf.length);
  }

  private static String toHex(byte[] buf, int ofs, int len) {
    StringBuffer sb = new StringBuffer();
    int j = ofs + len;
    for (int i = ofs; i < j; i++) {
      if (i < buf.length) {
        sb.append(hexchars[(buf[i] & 0xF0) >> 4]);
        sb.append(hexchars[buf[i] & 0x0F]);
        //sb.append(' ');
      }
    }
    return sb.toString().toLowerCase();
  }

}

