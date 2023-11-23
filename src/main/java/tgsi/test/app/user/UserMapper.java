package tgsi.test.app.user;

import java.util.List;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Options;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;

@Mapper
public interface UserMapper {
        @Select("SELECT * from user")
        public List<User> getAllUser();

        @Select("SELECT * FROM user WHERE id=#{id}")
        public List<User> getUserById(Long id);

        @Insert("INSERT INTO user (firstname, lastname, email, password, role, created_on, updated_on) " +
                        "VALUES (#{firstname}, #{lastname}, #{email}, #{password}, #{role}, NOW(6), NOW(6))")
        @Options(useGeneratedKeys = true, keyProperty = "id")
        public void insertUser(User user1);

        @Update("UPDATE user SET " +
                        "firstname = #{firstname}, " +
                        "lastname = #{lastname}, " +
                        "email = #{email}, " +
                        "password = #{password}, " +
                        "updated_on = now() " +
                        "WHERE id = #{id}")
        @Options(useGeneratedKeys = true)
        public void updateUser(User user);

        @Select("SELECT * FROM user WHERE email = #{email}")
        public User findByEmail(String email);

        // @Select("SELECT * FROM user WHERE role = #{roleOrdinal}")
        // public User findByRole(String role);
}
