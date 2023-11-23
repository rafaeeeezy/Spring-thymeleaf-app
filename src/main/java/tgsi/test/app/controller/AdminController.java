package tgsi.test.app.controller;

import java.util.HashMap;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import tgsi.test.app.auth.AuthenticationService;
import tgsi.test.app.student.StudentService;

@Controller
@RequiredArgsConstructor
public class AdminController {

    private final AuthenticationService authenticationService;
    private final StudentService studentService;

    @GetMapping("/admin")
    public String getAdmin(Model model, HttpServletResponse httpServletResponse,
            HttpServletRequest httpServletRequest) {
        System.out.println("admin controller");
        if (authenticationService.isAuthenticated(httpServletRequest, httpServletResponse)) {
            HashMap<String, String> cookies = authenticationService.getAllCookies(httpServletRequest);
            model.addAttribute("user", cookies);
            // model.addAttribute("message", "Hello from secured endpoint");
            System.out.println("admin controller: authenticated");
            if (cookies.get("role").equals("ADMIN")) {
                model.addAttribute("students", studentService.getAllStudents());
                return "/student/students";
            } else {
                return "unauthorized";
            }
        }
        return "login";

    }
}
