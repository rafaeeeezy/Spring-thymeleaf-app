package tgsi.test.app.controller;

import java.util.HashMap;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import tgsi.test.app.auth.AuthenticationService;

@Controller
@RequiredArgsConstructor
public class UserController {
    private final AuthenticationService authenticationService;

    @GetMapping("/user")
    public String getUser(Model model, HttpServletResponse httpServletResponse, HttpServletRequest httpServletRequest) {
        System.out.println("admin controller");
        if (authenticationService.isAuthenticated(httpServletRequest, httpServletResponse)) {
            HashMap<String, String> cookies = authenticationService.getAllCookies(httpServletRequest);
            model.addAttribute("user", cookies);
            System.out.println("user controller: authenticated");
            if (cookies.get("role").equals("USER")) {
                return "/user/index";
            } else {
                return "unauthorized";
            }
        }
        return "login";
    }
}
