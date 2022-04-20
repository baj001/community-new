//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.nowcoder.community.config;

import com.nowcoder.community.controller.interceptor.AlphaInterceptor;
import com.nowcoder.community.controller.interceptor.DataInterceptor;
import com.nowcoder.community.controller.interceptor.LoginTicketInterceptor;
import com.nowcoder.community.controller.interceptor.MessageInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebMvcConfig implements WebMvcConfigurer {
    @Autowired
    private AlphaInterceptor alphaInterceptor;
    @Autowired
    private LoginTicketInterceptor loginTicketInterceptor;
    @Autowired
    private MessageInterceptor messageInterceptor;
    @Autowired
    private DataInterceptor dataInterceptor;

    public WebMvcConfig() {
    }

    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(this.alphaInterceptor).excludePathPatterns(new String[]{"/**/*.css", "/**/*.js", "/**/*.png", "/**/*.jpg", "/**/*.jpeg"}).addPathPatterns(new String[]{"/register", "/login"});
        registry.addInterceptor(this.loginTicketInterceptor).excludePathPatterns(new String[]{"/**/*.css", "/**/*.js", "/**/*.png", "/**/*.jpg", "/**/*.jpeg"});
        registry.addInterceptor(this.messageInterceptor).excludePathPatterns(new String[]{"/**/*.css", "/**/*.js", "/**/*.png", "/**/*.jpg", "/**/*.jpeg"});
        registry.addInterceptor(this.dataInterceptor).excludePathPatterns(new String[]{"/**/*.css", "/**/*.js", "/**/*.png", "/**/*.jpg", "/**/*.jpeg"});
    }
}
