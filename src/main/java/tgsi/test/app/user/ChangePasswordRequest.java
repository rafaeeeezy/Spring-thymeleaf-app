package tgsi.test.app.user;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ChangePasswordRequest {

    private String currentPassword;
    private String newPassword;
    private String confirmationPassword;

    // public ChangePasswordRequest() {
    // // Default constructor
    // }

    // public ChangePasswordRequest(String currentPassword, String newPassword,
    // String confirmationPassword) {
    // this.currentPassword = currentPassword;
    // this.newPassword = newPassword;
    // this.confirmationPassword = confirmationPassword;
    // }
}