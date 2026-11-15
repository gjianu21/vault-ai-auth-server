package com.vaultai.auth.controller;

import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import com.vaultai.auth.config.AppProperties;

import lombok.RequiredArgsConstructor;

/** Values available in every Thymeleaf page. */
@ControllerAdvice
@RequiredArgsConstructor
public class GlobalModelAttributes {

    private final AppProperties properties;

    @ModelAttribute("frontendUrl")
    public String frontendUrl() {
        return properties.frontendUrl();
    }
}