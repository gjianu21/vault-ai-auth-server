package com.vaultai.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.vaultai.auth.dto.RegisterForm;
import com.vaultai.auth.exception.InvalidTokenException;
import com.vaultai.auth.exception.TokenExpiredException;
import com.vaultai.auth.service.RegistrationService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class RegistrationController {

    private final RegistrationService registrationService;

    @GetMapping("/register")
    public String registerForm(Model model) {
        model.addAttribute("form", new RegisterForm());
        return "register";
    }

    @PostMapping("/register")
    public String register(@Valid @ModelAttribute("form") RegisterForm form, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "register";
        }
        registrationService.register(form.getEmail(), form.getPassword());
        return "redirect:/register/done";
    }

    @GetMapping("/register/done")
    public String registerDone() {
        return "register-done";
    }

    @GetMapping("/verify-email")
    public String verifyEmail(@RequestParam(name = "token", required = false) String token, Model model) {
        try {
            registrationService.verifyEmail(token);
            model.addAttribute("status", "success");
        } catch (TokenExpiredException ex) {
            model.addAttribute("status", "expired");
        } catch (InvalidTokenException ex) {
            model.addAttribute("status", "invalid");
        }
        return "verify-result";
    }
}