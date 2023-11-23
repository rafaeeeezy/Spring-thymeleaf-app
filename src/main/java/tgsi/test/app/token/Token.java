package tgsi.test.app.token;

import tgsi.test.app.user.User;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Token {

  public Integer id;

  public String token;

  public TokenType token_type = TokenType.BEARER;

  public boolean revoked;

  public boolean expired;

  public User user;

  public Integer user_id;

  public Integer get_user_id() {
    return this.user.getId();
  }
}
