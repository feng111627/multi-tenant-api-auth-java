package com.github.feng111627.multitenantapiauthjava.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ReadListener;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * 请求体缓存过滤器：把 body 读出来缓存，使验签拦截器和后续控制器都能重复读取。
 */
@Component
public class CachedBodyFilter extends OncePerRequestFilter {

    public static final String CACHED_BODY_ATTR = CachedBodyFilter.class.getName() + ".CACHED_BODY";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        byte[] body = request.getInputStream().readAllBytes();
        CachedBodyRequestWrapper wrapper = new CachedBodyRequestWrapper(request, body);
        request.setAttribute(CACHED_BODY_ATTR, body);
        chain.doFilter(wrapper, response);
    }

    /**
     * 取出缓存的请求体（无缓存时返回空串）。
     */
    public static String cachedBody(HttpServletRequest request) {
        Object attr = request.getAttribute(CACHED_BODY_ATTR);
        if (attr instanceof byte[] bytes) {
            return new String(bytes, StandardCharsets.UTF_8);
        }
        return "";
    }

    static final class CachedBodyRequestWrapper extends HttpServletRequestWrapper {
        private final byte[] body;

        CachedBodyRequestWrapper(HttpServletRequest request, byte[] body) {
            super(request);
            this.body = body;
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream in = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return in.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener readListener) {
                }

                @Override
                public int read() {
                    return in.read();
                }
            };
        }

        @Override
        public BufferedReader getReader() {
            return new BufferedReader(new InputStreamReader(getInputStream(), StandardCharsets.UTF_8));
        }
    }
}
