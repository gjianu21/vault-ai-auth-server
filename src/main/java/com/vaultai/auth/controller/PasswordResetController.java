package com.vaultai.auth.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.vaultai.auth.dto.ForgotPasswordForm;
import com.vaultai.auth.dto.ResetPasswordForm;
import com.vaultai.auth.exception.InvalidTokenException;
import com.vaultai.auth.exception.TokenExpiredException;
import com.vaultai.auth.service.PasswordResetService;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class PasswordResetController {

    private final PasswordResetService passwordResetService;

    @GetMapping("/forgot-password")
    public String forgotPasswordForm(Model model) {
        model.addAttribute("form", new ForgotPasswordForm());
        return "forgot-password";
    }

    @PostMapping("/forgot-password")
    public String forgotPassword(@Valid @ModelAttribute("form") ForgotPasswordForm form,
                                 BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return "forgot-password";
        }
        passwordResetService.requestReset(form.getEmail());
        return "redirect:/forgot-password/done";
    }

    @GetMapping("/forgot-password/done")
    public String forgotPasswordDone() {
        return "forgot-password-done";
    }

    @GetMapping("/reset-password")
    public String resetPasswordForm(@RequestParam(name = "token", required = false) String token,
                                    @RequestParam(name = "blocked", required = false) String blocked,
                                    Model model) {
        if (blocked != null) {
            model.addAttribute("status", "blocked");
            return "reset-result";
        }
        try {
            passwordResetService.validateToken(token);
        } catch (TokenExpiredException ex) {
            model.addAttribute("status", "expired");
            return "reset-result";
        } catch (InvalidTokenException ex) {
            model.addAttribute("status", "invalid");
            return "reset-result";
        }

        ResetPasswordForm form = new ResetPasswordForm();
        form.setToken(token);
        model.addAttribute("form", form);
        return "reset-password";
    }

    @PostMapping("/reset-password")
    public String resetPassword(@Valid @ModelAttribute("form") ResetPasswordForm form,
                                BindingResult bindingResult, Model model) {
        if (bindingResult.hasErrors()) {
            return "reset-password";
        }
        try {
            passwordResetService.resetPassword(form.getToken(), form.getPassword());
            model.addAttribute("status", "success");
        } catch (TokenExpiredException ex) {
            model.addAttribute("status", "expired");
        } catch (InvalidTokenException ex) {
            model.addAttribute("status", "invalid");
        }
        return "reset-result";
    }
}