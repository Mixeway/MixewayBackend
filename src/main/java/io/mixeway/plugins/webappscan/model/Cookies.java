package io.mixeway.plugins.webappscan.model;

import io.mixeway.db.entity.WebApp;
import io.mixeway.db.entity.WebAppCookies;

import java.util.ArrayList;
import java.util.List;

public class Cookies {
    private List<CustomCookie> custom_cookies;
    public List<CustomCookie> getCustom_cookies() {
        return custom_cookies;
    }

    public void setCustom_cookies(List<CustomCookie> custom_cookies) {
        this.custom_cookies = custom_cookies;
    }
    public Cookies(WebApp wa) {
        List<CustomCookie> customCookies = new ArrayList<>();
        for (WebAppCookies cookies : wa.getWebAppCookies()){
            CustomCookie customCookie = new CustomCookie();
            customCookie.setCookie(cookies.getCookie());
            customCookie.setUrl(cookies.getUrl());
            customCookies.add(customCookie);
        }
        this.setCustom_cookies(customCookies);
    }
}
