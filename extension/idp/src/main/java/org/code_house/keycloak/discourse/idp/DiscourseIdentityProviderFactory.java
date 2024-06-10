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

import java.util.List;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ConfiguredProvider;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class DiscourseIdentityProviderFactory extends AbstractIdentityProviderFactory<DiscourseIdentityProvider>
  implements SocialIdentityProviderFactory<DiscourseIdentityProvider>, ConfiguredProvider {

  @Override
  public String getName() {
    return "Discourse";
  }

  @Override
  public DiscourseIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new DiscourseIdentityProvider(session, new DiscourseIdentityProviderConfig(model));
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return ProviderConfigurationBuilder.create()
        .property()
          .name("discourseAddress")
          .label("Discourse root URL")
          .helpText("Address where forum is running, please provide link to forum homepage")
          .type(ProviderConfigProperty.STRING_TYPE)
        .add()
      .build();
  }

  @Override
  public DiscourseIdentityProviderConfig createConfig() {
    return new DiscourseIdentityProviderConfig();
  }

  @Override
  public String getId() {
    return "discourse";
  }
}
