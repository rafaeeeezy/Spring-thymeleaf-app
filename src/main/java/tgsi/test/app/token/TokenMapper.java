package tgsi.test.app.token;

import java.util.List;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

@Mapper
public interface TokenMapper {

        @Select("SELECT * from token")
        public List<Token> getAllToken();

        @Select("SELECT * FROM token WHERE id=#{id}")
        public List<Token> getTokenById(Long id);

        @Insert("INSERT INTO token (token, user_id, revoked, expired, token_type) " +
                        "VALUES (#{token}, #{user_id}, #{revoked}, #{expired}, #{token_type})")
        @Options(keyProperty = "id")
        public void insertToken(Token token);

        @Select("SELECT t.* FROM token t " +
                        "INNER JOIN User u ON t.user_id = u.id " +
                        "WHERE u.id = #{id} AND (t.expired = 0 OR t.revoked = 0)")
        List<Token> findAllValidTokenByUser(Integer id);

        @Select("SELECT * FROM token WHERE token = #{token}")
        Token findByToken(String token);

        @Update({
                        "<script>",
                        "UPDATE Token",
                        "SET expired = 1, revoked = 1",
                        "WHERE id IN",
                        "<foreach collection='tokens' item='token' open='(' separator=',' close=')'>",
                        "#{token.id}",
                        "</foreach>",
                        "</script>"
        })
        void updateTokens(List<Token> tokens);
}
