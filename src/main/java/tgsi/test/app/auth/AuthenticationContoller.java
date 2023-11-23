package tgsi.test.app.auth;

import java.util.HashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import tgsi.test.app.student.StudentService;
import tgsi.test.app.user.Role;
import tgsi.test.app.user.User;
import tgsi.test.app.user.UserMapper;

@Controller
@RequiredArgsConstructor
public class AuthenticationContoller {

    public static final Pattern VALID_EMAIL_ADDRESS_REGEX = Pattern.compile(
            "^(?=.{1,64}@)[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*@[^-][A-Za-z0-9-]+(\\.[A-Za-z0-9-]+)*(\\.[A-Za-z]{2,})$",
            Pattern.CASE_INSENSITIVE);

    public static final Pattern VALID_PASSWORD_REGEX = Pattern.compile(
            "^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%]).{8,24}$",
            Pattern.CASE_INSENSITIVE);

    public static boolean isValidPassword(String passwordStr) {
        Matcher matcher = VALID_PASSWORD_REGEX.matcher(passwordStr);
        return matcher.matches();
    }

    public static boolean isValidEmail(String emailStr) {
        Matcher matcher = VALID_EMAIL_ADDRESS_REGEX.matcher(emailStr);
        return matcher.matches();
    }

    // isValidEmail(hello@example.com") //
    private final AuthenticationService authenticationService;
    private final UserMapper userMapper;
    private final StudentService studentService;

    @GetMapping("/")
    public String index(Model model, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        if (authenticationService.isAuthenticated(httpServletRequest, httpServletResponse)) {
            HashMap<String, String> cookies = authenticationService.getAllCookies(httpServletRequest);
            model.addAttribute("user", cookies);
            model.addAttribute("students", studentService.getAllStudents());
            // model.addAttribute("message", "Hello from secured endpoint");
            System.out.println("admin controller: authenticated");
            if (cookies.get("role").equals("ADMIN")) {
                return "/student/students";
            } else if (cookies.get("role").equals("USER")) {
                return "/user/index";
            } else if (cookies.get("role").equals("MANAGER")) {
                return "/manager/index";
            } else {
                return "unauthorized";
            }
        } else {
            return "redirect:/home";
        }
    }

    @GetMapping("/home")
    public String home(Model model, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        if (authenticationService.isAuthenticated(httpServletRequest, httpServletResponse)) {
            HashMap<String, String> cookies = authenticationService.getAllCookies(httpServletRequest);
            model.addAttribute("user", cookies);
        }
        return "login";
    }

    @GetMapping("/login")
    public String signin(Model model, HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {

        if (authenticationService.isAuthenticated(httpServletRequest, httpServletResponse)) {

            return "redirect:/";
        } else {
            return "login";
        }
    }

    @GetMapping("/register")
    public String showRegistrationForm(Model model, HttpServletRequest httpServletRequest,
            HttpServletResponse httpServletResponse) {
        if (authenticationService.isAuthenticated(httpServletRequest, httpServletResponse)) {

            return "redirect:/";
        } else {
            RegisterRequest registerRequest = new RegisterRequest();
            model.addAttribute("user", registerRequest);
            return "register";
        }

    }

    @PostMapping("/auth/authenticate")
    public String authenticate(
            @ModelAttribute("user") AuthenticationRequest authenticationRequest,
            BindingResult result,
            Model model,
            HttpServletResponse httpServletResponse,
            HttpServletRequest httpServletRequest) {
        System.out.println("TestContoller.authenticate");
        System.out.println("user: " + authenticationRequest);
        System.out.println("result: " + result);
        System.out.println("model: " + model);
        final String email = authenticationRequest.getEmail();
        final String password = authenticationRequest.getPassword();

        if (isNullOrEmpty(email)) {
            System.out.println("email is null or empty");
            model.addAttribute("error", "Email cannot be empty");
        } else if (isNullOrEmpty(password)) {
            System.out.println("password is null or empty");
            model.addAttribute("error", "Password cannot be empty");
        } else {
            AuthenticationResponse authResponse = authenticationService.authenticate(authenticationRequest,
                    httpServletRequest,
                    httpServletResponse);

            if (authResponse == null) {
                System.out.println("authResponse is null");
                model.addAttribute("error", "Incorrect username or password");
            } else {

                System.out.println("access token: " + authResponse.getAccessToken());
                System.out.println("refresh token: " + authResponse.getRefreshToken());
                System.out.println("role: " + authResponse.getRole());

                Cookie refreshTokenCookie = new Cookie("refreshToken", authResponse.getRefreshToken());
                refreshTokenCookie.setHttpOnly(true);
                refreshTokenCookie.setPath("/");
                refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
                model.addAttribute("refreshToken", refreshTokenCookie.getValue());
                httpServletResponse.addCookie(refreshTokenCookie);

                Cookie accessTokenCookie = new Cookie("accessToken", authResponse.getAccessToken());
                accessTokenCookie.setHttpOnly(true);
                accessTokenCookie.setPath("/");
                accessTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
                model.addAttribute("accessToken", accessTokenCookie.getValue());
                httpServletResponse.addCookie(accessTokenCookie);

                Cookie emailCookie = new Cookie("email", authenticationRequest.getEmail());
                emailCookie.setHttpOnly(true);
                emailCookie.setPath("/");
                emailCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
                model.addAttribute("email", emailCookie.getValue());
                httpServletResponse.addCookie(emailCookie);

                Cookie roleCookie = new Cookie("role", authResponse.getRole().toString());
                roleCookie.setHttpOnly(true);
                roleCookie.setPath("/");
                roleCookie.setMaxAge(7 * 24 * 60 * 60); // 7 days
                model.addAttribute("role", roleCookie.getValue());
                httpServletResponse.addCookie(roleCookie);

                System.out.println("refreshtoken cookie: " + refreshTokenCookie.getValue());
                System.out.println("accesstoken cookie: " + accessTokenCookie.getValue());
                System.out.println("email cookie: " + emailCookie.getValue());
                System.out.println("role cookie: " + roleCookie.getValue());

                httpServletResponse.setHeader(HttpHeaders.AUTHORIZATION, "Bearer " + authResponse.getAccessToken());

                return "redirect:/";
            }
        }

        model.addAttribute("user", authenticationRequest);
        return "login";
    }

    @PostMapping("/auth/register/save")
    public String registration(
            @ModelAttribute("user") RegisterRequest registerRequest,
            BindingResult result,
            Model model,
            HttpServletResponse response) {
        registerRequest.setRole(Role.USER);
        System.out.println("TestContoller.registration");
        System.out.println("user: " + registerRequest);
        System.out.println("result: " + result);
        System.out.println("model: " + model);
        User existing = userMapper.findByEmail(registerRequest.getEmail());

        if (isNullOrEmpty(registerRequest.getFirstname())) {
            // result.rejectValue("firstName", null, "First name cannot be empty");
            model.addAttribute("error", "First name cannot be empty");
        } else if (isNullOrEmpty(registerRequest.getLastname())) {
            model.addAttribute("error", "Last name cannot be empty");
        } else if (isNullOrEmpty(registerRequest.getEmail())) {
            model.addAttribute("error", "Email cannot be empty");
        } else if (isNullOrEmpty(registerRequest.getPassword())) {
            model.addAttribute("error", "Password cannot be empty");
        } else if (isValidEmail(registerRequest.getEmail()) == false) {
            model.addAttribute("error", "Invalid email format! Please enter a valid email address.");
        } else if (isValidPassword(registerRequest.getPassword()) == false) {
            model.addAttribute("error",
                    "8 to 24 characters. Must include uppercase and lowercase letters, a number and a special character.\n Allowed special characters: ! @ # $ % ");
        } else if (existing != null) {
            model.addAttribute("error", "There is already an account registered with that email");
        } else {
            try {
                System.out.println("registerRequest: " + registerRequest);
                registerRequest.setRole(Role.USER);

                AuthenticationResponse authResponse = authenticationService.register(registerRequest);
                System.out.println("access token: " + authResponse.getAccessToken());
                System.out.println("refresh token: " + authResponse.getRefreshToken());
                System.out.println("role: " + authResponse.getRole());
                System.out.println("email: " + authResponse.getEmail());

            } catch (Exception e) {
                System.out.println("Something went wrong:");
                System.out.println(e.getMessage());
                e.printStackTrace();
                return "redirect:/register?error";
            }
            return "redirect:/login?success";
        }

        model.addAttribute("user", registerRequest);
        return "register";

    }

    @RequestMapping("/logout")
    public String logout(Model model) {
        return "redirect:/login?logout";
    }

    private boolean isNullOrEmpty(String str) {
        return str == null || str.trim().isEmpty();
    }
}
