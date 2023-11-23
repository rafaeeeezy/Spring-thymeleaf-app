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
public class ManagerController {

    private final AuthenticationService authenticationService;

    @GetMapping("/manager")
    public String getAdmin(Model model, HttpServletResponse httpServletResponse,
            HttpServletRequest httpServletRequest) {
        System.out.println("admin controller");
        if (authenticationService.isAuthenticated(httpServletRequest, httpServletResponse)) {
            HashMap<String, String> cookies = authenticationService.getAllCookies(httpServletRequest);
            model.addAttribute("user", cookies);
            // model.addAttribute("message", "Hello from secured endpoint");
            System.out.println("manager controller: authenticated");
            if (cookies.get("role").equals("MANAGER")) {
                return "/manager/index";
            } else {
                return "unauthorized";
            }
        }
        return "login";

    }
}
