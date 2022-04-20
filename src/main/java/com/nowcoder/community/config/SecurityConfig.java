//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.nowcoder.community.config;

import com.nowcoder.community.util.CommunityConstant;
import com.nowcoder.community.util.CommunityUtil;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer.AuthorizedUrl;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter implements CommunityConstant {
    public SecurityConfig() {
    }

    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(new String[]{"/resources/**"});
    }

    protected void configure(HttpSecurity http) throws Exception {
        ((HttpSecurity)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)((AuthorizedUrl)http.authorizeRequests().antMatchers(new String[]{"/user/setting", "/user/upload", "/discuss/add", "/comment/add/**", "/letter/**", "/notice/**", "/like", "/follow", "/unfollow"})).hasAnyAuthority(new String[]{"user", "admin", "moderator"}).antMatchers(new String[]{"/discuss/top", "/discuss/wonderful"})).hasAnyAuthority(new String[]{"moderator"}).antMatchers(new String[]{"/discuss/delete", "/data/**"})).hasAnyAuthority(new String[]{"admin"}).anyRequest()).permitAll().and()).csrf().disable();
        http.exceptionHandling().authenticationEntryPoint(new AuthenticationEntryPoint() {
            public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                String xRequestedWith = request.getHeader("x-requested-with");
                if ("XMLHttpRequest".equals(xRequestedWith)) {
                    response.setContentType("application/plain;charset=utf-8");
                    PrintWriter writer = response.getWriter();
                    writer.write(CommunityUtil.getJSONString(403, "你还没有登录哦!"));
                } else {
                    response.sendRedirect(request.getContextPath() + "/login");
                }

            }
        }).accessDeniedHandler(new AccessDeniedHandler() {
            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException e) throws IOException, ServletException {
                String xRequestedWith = request.getHeader("x-requested-with");
                if ("XMLHttpRequest".equals(xRequestedWith)) {
                    response.setContentType("application/plain;charset=utf-8");
                    PrintWriter writer = response.getWriter();
                    writer.write(CommunityUtil.getJSONString(403, "你没有访问此功能的权限!"));
                } else {
                    response.sendRedirect(request.getContextPath() + "/denied");
                }

            }
        });
        http.logout().logoutUrl("/securitylogout");
    }
}
