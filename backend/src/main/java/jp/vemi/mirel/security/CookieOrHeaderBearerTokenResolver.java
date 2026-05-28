/*
 * Copyright(c) 2015-2025 mirelplatform.
 */
package jp.vemi.mirel.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.util.StringUtils;

import jp.vemi.framework.util.SanitizeUtil;

import java.util.Set;

/**
 * Cookie または Authorization ヘッダーからJWTを読み取るBearerTokenResolver.
 * 
 * 優先順位:
 * 1. Authorization: Bearer <token>
 * 2. Cookie: accessToken=<token>
 * 
 * 認証不要パス（/auth/login等）ではJWT解決をスキップし、
 * 古い/無効なJWTがCookieに残っていてもリクエストが阻害されないようにする。
 */
public class CookieOrHeaderBearerTokenResolver implements BearerTokenResolver {

    private static final Logger logger = LoggerFactory.getLogger(CookieOrHeaderBearerTokenResolver.class);
    private static final String COOKIE_NAME = "accessToken";

    /**
     * JWT解決をスキップするパス（認証不要エンドポイント）.
     * これらのパスでは古い/無効なJWTがCookieに残っていても無視される。
     */
    private static final Set<String> SKIP_JWT_PATHS = Set.of(
            "/auth/login",
            "/auth/signup",
            "/auth/logout",
            "/auth/health",
            "/auth/otp/",
            "/auth/refresh",
            "/auth/verify-setup-token",
            "/auth/setup-account",
            "/api/bootstrap/",
            "/api/auth/device/");

    @Override
    public String resolve(HttpServletRequest request) {
        // コンテキストパスを除去してパスを取得
        String path = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (StringUtils.hasText(contextPath)) {
            path = path.substring(contextPath.length());
        }

        // 認証不要パスではJWT解決をスキップ
        final String normalizedPath = path;
        if (SKIP_JWT_PATHS.stream()
                .anyMatch(skipPath -> normalizedPath.equals(skipPath) || normalizedPath.startsWith(skipPath))) {
            // lgtm[java/log-injection] - path is sanitized with SanitizeUtil.forLog()
            logger.debug("Skipping JWT resolution for public path: {}", SanitizeUtil.forLog(normalizedPath));
            return null;
        }

        // 1. Authorization ヘッダーから取得（優先）
        String authHeader = request.getHeader("Authorization");
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            logger.debug("JWT resolved from Authorization header");
            return token;
        }

        // 2. Cookie から取得（フォールバック）
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    String token = cookie.getValue();
                    if (StringUtils.hasText(token)) {
                        logger.debug("JWT resolved from Cookie: {}", COOKIE_NAME);
                        return token;
                    }
                }
            }
        }

        logger.debug("No JWT found in Authorization header or Cookie");
        return null;
    }
}
