/*
 * Copyright(c) 2015-2024 mirelplatform.
 */
package jp.vemi.mirel.foundation.web.api.auth.controller;

import jakarta.validation.Valid;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jp.vemi.mirel.foundation.context.ExecutionContext;
import jp.vemi.mirel.foundation.web.api.auth.dto.*;
import jp.vemi.mirel.foundation.web.api.auth.service.AuthenticationServiceImpl;
import jp.vemi.mirel.foundation.web.api.auth.service.PasswordResetService;
import jp.vemi.mirel.foundation.web.api.dto.ApiRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import jp.vemi.framework.util.SanitizeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 認証APIコントローラ.
 */
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    private ExecutionContext executionContext;

    @Autowired
    private AuthenticationServiceImpl authenticationService;

    @Autowired
    private PasswordResetService passwordResetService;

    @Autowired
    private jp.vemi.mirel.config.properties.AuthProperties authProperties;

    /**
     * ログイン
     */
    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {

            // IP と UserAgent を注入
            request.setIpAddress(getClientIp(httpRequest));
            request.setUserAgent(httpRequest.getHeader("User-Agent"));

            AuthenticationResponse response = authenticationService.login(request);

            // Set access token in HttpOnly cookie
            if (response.getTokens() != null) {
                setTokenCookies(httpResponse, response.getTokens());
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Login failed: {}", e.getMessage());
            return ResponseEntity.status(401).build();
        }
    }

    /**
     * サインアップ
     */
    @PostMapping("/signup")
    public ResponseEntity<AuthenticationResponse> signup(
            @Valid @RequestBody SignupRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {

            AuthenticationResponse response = authenticationService.signup(request);

            // Set access token in HttpOnly cookie
            if (response.getTokens() != null) {
                setTokenCookies(httpResponse, response.getTokens());
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Signup failed: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * OAuth2サインアップ（既存のSystemUserにUserを紐付け）
     */
    @PostMapping("/signup/oauth2")
    public ResponseEntity<AuthenticationResponse> signupOAuth2(
            @Valid @RequestBody OAuth2SignupRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {

            // 認証済み（SystemUserとして）であることを確認
            org.springframework.security.core.Authentication auth = org.springframework.security.core.context.SecurityContextHolder
                    .getContext().getAuthentication();

            if (auth == null || !auth.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            AuthenticationResponse response = authenticationService.signupWithOAuth2(request, auth.getName());

            // Set access token in HttpOnly cookie
            if (response.getTokens() != null) {
                setTokenCookies(httpResponse, response.getTokens());
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("OAuth2 signup failed: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * OTPベースサインアップ
     * メールアドレス検証済みのユーザーを作成
     */
    /**
     * OTPベースサインアップ
     * 
     * @deprecated Use /auth/otp/signup-verify instead for better security
     */
    @Deprecated
    @PostMapping("/signup/otp")
    public ResponseEntity<AuthenticationResponse> signupOtp(
            @Valid @RequestBody jp.vemi.mirel.foundation.web.api.auth.dto.OtpSignupRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {

            AuthenticationResponse response = authenticationService.signupWithOtp(request);

            // Set access token in HttpOnly cookie
            if (response.getTokens() != null) {
                setTokenCookies(httpResponse, response.getTokens());
            }

            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            logger.error("OTP signup failed: {}", e.getMessage());

            // エラーメッセージに応じた適切なHTTPステータスコードを返す
            String errorMessage = e.getMessage();
            if (errorMessage != null) {
                if (errorMessage.contains("Username already exists") ||
                        errorMessage.contains("Email already exists")) {
                    return ResponseEntity.status(409).build(); // Conflict
                }
            }

            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * トークンリフレッシュ
     * body の refreshToken を優先し、未指定なら Cookie "refreshToken" にフォールバック。
     * これにより F5/新規タブ後もメモリが空でも Cookie 経由で refresh 可能。
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(
            @RequestBody(required = false) RefreshTokenRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {
            // body から refreshToken を取得、なければ Cookie から取得
            String refreshTokenValue = (request != null && request.getRefreshToken() != null)
                    ? request.getRefreshToken()
                    : resolveRefreshTokenFromCookie(httpRequest);

            if (refreshTokenValue == null || refreshTokenValue.isEmpty()) {
                logger.warn("Token refresh failed: no refresh token in body or cookie");
                return ResponseEntity.status(401).build();
            }

            // 統一した refreshToken を使って request を組み立て
            if (request == null) {
                request = new RefreshTokenRequest();
            }
            request.setRefreshToken(refreshTokenValue);

            AuthenticationResponse response = authenticationService.refresh(request);

            // Set tokens in HttpOnly cookies (access + new refresh after rotation)
            if (response.getTokens() != null) {
                setTokenCookies(httpResponse, response.getTokens());
            }

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Token refresh failed: {}", e.getMessage());
            return ResponseEntity.status(401).build();
        }
    }

    /**
     * HttpServletRequest の Cookie から refreshToken を取得
     */
    private String resolveRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("refreshToken".equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }

    /**
     * ログアウト
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestBody(required = false) RefreshTokenRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {
        try {
            String refreshToken = request != null ? request.getRefreshToken() : null;
            authenticationService.logout(refreshToken);

            // Clear cookies
            clearTokenCookies(httpResponse);

            return ResponseEntity.ok().build();
        } catch (Exception e) {
            logger.error("Logout failed: {}", e.getMessage());

            // Clear cookies even on error
            clearTokenCookies(httpResponse);

            return ResponseEntity.ok().build(); // Always return 200 for logout
        }
    }

    /**
     * テナント切替
     */
    @PostMapping("/switch-tenant")
    public ResponseEntity<UserContextDto> switchTenant(@RequestBody SwitchTenantRequest request) {
        try {
            if (!executionContext.isAuthenticated()) {
                return ResponseEntity.status(401).build();
            }

            String userId = executionContext.getCurrentUserId();
            UserContextDto response = authenticationService.switchTenant(userId, request.getTenantId());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Tenant switch failed: {}", e.getMessage());
            return ResponseEntity.status(403).build();
        }
    }

    /**
     * 現在のユーザ情報を取得
     */
    @GetMapping("/me")
    public ResponseEntity<UserContextDto> getCurrentUser() {
        logger.info("GET /auth/me - Getting current user context");

        if (!executionContext.isAuthenticated()) {
            return ResponseEntity.status(401).build();
        }

        try {
            var user = executionContext.getCurrentUser();
            var tenant = executionContext.getCurrentTenant();

            UserContextDto response = UserContextDto.builder()
                    .user(UserDto.builder()
                            .userId(user.getUserId())
                            .username(user.getUsername())
                            .email(user.getEmail())
                            .displayName(user.getDisplayName())
                            .firstName(user.getFirstName())
                            .lastName(user.getLastName())
                            .isActive(user.getIsActive())
                            .emailVerified(user.getEmailVerified())
                            .build())
                    .currentTenant(tenant != null ? TenantContextDto.builder()
                            .tenantId(tenant.getTenantId())
                            .tenantName(tenant.getTenantName())
                            .displayName(tenant.getDisplayName())
                            .build() : null)
                    .build();

            logger.info("Returning user context for user: {}, tenant: {}",
                    user.getUserId(), tenant != null ? tenant.getTenantId() : "none");

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Failed to get current user context", e);
            return ResponseEntity.status(500).build();
        }
    }

    /**
     * ヘルスチェック用エンドポイント
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("OK");
    }

    /**
     * アカウントセットアップトークン検証
     * 管理者が作成したユーザーのセットアップリンク検証
     */
    @GetMapping("/verify-setup-token")
    public ResponseEntity<?> verifySetupToken(@RequestParam String token) {
        try {
            VerifySetupTokenResponse response = authenticationService.verifyAccountSetupToken(token);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid setup token: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "INVALID_TOKEN", "message", "無効なセットアップトークンです"));
        } catch (RuntimeException e) {
            logger.error("Setup token verification failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "VERIFICATION_FAILED", "message", "トークンの検証に失敗しました"));
        }
    }

    /**
     * アカウントセットアップ（パスワード設定）
     * 管理者が作成したユーザーが初回パスワードを設定
     */
    @PostMapping("/setup-account")
    public ResponseEntity<?> setupAccount(@Valid @RequestBody ApiRequest<SetupAccountRequest> apiRequest) {
        try {
            SetupAccountRequest request = apiRequest.getModel();
            logger.info("Setup account request: passwordLength={}",
                    request.getNewPassword() != null ? request.getNewPassword().length() : 0);
            authenticationService.setupAccount(request.getToken(), request.getNewPassword());
            logger.info("Account setup completed successfully");
            return ResponseEntity.ok(Map.of("message", "アカウントのセットアップが完了しました"));
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid setup request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("error", "INVALID_REQUEST", "message", "リクエストが無効です"));
        } catch (RuntimeException e) {
            logger.error("Account setup failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "SETUP_FAILED", "message", "アカウントのセットアップに失敗しました"));
        }
    }

    /**
     * 検証メール再送
     * ユーザーが自分で検証メールを再送できるようにする
     */
    @PostMapping("/resend-verification")
    public ResponseEntity<Map<String, String>> resendVerification(
            @Valid @RequestBody ResendVerificationRequest request,
            HttpServletRequest httpRequest) {

        String ipAddress = getClientIp(httpRequest);
        String userAgent = httpRequest.getHeader("User-Agent");

        try {
            authenticationService.resendVerificationEmail(
                    request.getEmail(),
                    ipAddress,
                    userAgent);
        } catch (Exception e) {
            logger.warn("Verification email resend error: {}", SanitizeUtil.forLog(request.getEmail()), e);
            // エラー詳細を返さない（セキュリティ）
        }

        // セキュリティ: 成功/失敗に関わらず同じレスポンス
        return ResponseEntity.ok(
                Map.of("message", "検証メールを送信しました。受信ボックスを確認してください。"));
    }

    /**
     * パスワードリセット要求
     * トークンを生成し、メール送信の準備をする
     */
    @PostMapping("/password-reset-request")
    public ResponseEntity<String> requestPasswordReset(
            @Valid @RequestBody PasswordResetRequestDto request,
            HttpServletRequest httpRequest) {
        try {
            String clientIp = getClientIp(httpRequest);
            String userAgent = httpRequest.getHeader("User-Agent");

            passwordResetService.requestPasswordReset(
                    request.getEmail(),
                    clientIp,
                    userAgent);

            logger.info("Password reset requested for email: {}", SanitizeUtil.forLog(request.getEmail()));

            // セキュリティ: 成功/失敗に関わらず同じレスポンス（ユーザー列挙攻撃対策）
            return ResponseEntity.ok("Password reset email sent");

        } catch (IllegalArgumentException e) {
            // Don't reveal if user exists - always return success
            logger.warn("Password reset requested for non-existent email: {}", SanitizeUtil.forLog(request.getEmail()));
            return ResponseEntity.ok("Password reset email sent");
        } catch (Exception e) {
            logger.error("Password reset request failed", e);
            return ResponseEntity.status(500).body("Error processing request");
        }
    }

    /**
     * パスワードリセット実行
     * トークンを検証して新しいパスワードを設定
     */
    @PostMapping("/password-reset")
    public ResponseEntity<String> resetPassword(@Valid @RequestBody PasswordResetDto request) {
        try {
            passwordResetService.resetPassword(request.getToken(), request.getNewPassword());
            logger.info("Password reset successful");
            return ResponseEntity.ok("Password reset successful");
        } catch (IllegalArgumentException e) {
            logger.error("Password reset failed: Invalid token");
            return ResponseEntity.status(400).body("Invalid or expired token");
        } catch (IllegalStateException e) {
            logger.error("Password reset failed: {}", e.getMessage());
            return ResponseEntity.status(400).body("Password reset failed due to invalid state");
        } catch (Exception e) {
            logger.error("Password reset failed", e);
            return ResponseEntity.status(500).body("Error processing request");
        }
    }

    /**
     * トークン検証エンドポイント（オプショナル）
     * フロントエンドがトークンの有効性を事前確認するために使用
     */
    @GetMapping("/password-reset/verify")
    public ResponseEntity<Boolean> verifyResetToken(@RequestParam String token) {
        boolean isValid = passwordResetService.verifyToken(token);
        return ResponseEntity.ok(isValid);
    }

    /**
     * Set JWT tokens as HttpOnly cookies.
     * Cookie maxAge は AuthProperties の値と一致させる。
     */
    private void setTokenCookies(HttpServletResponse response, TokenDto tokens) {
        // Access token cookie (HttpOnly, Secure in production)
        Cookie accessTokenCookie = new Cookie("accessToken", tokens.getAccessToken());
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setSecure(false); // Set true in production with HTTPS
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge((int) authProperties.getJwt().getExpiration()); // auth.jwt.expiration (default 1h)
        response.addCookie(accessTokenCookie);

        // Refresh token cookie (HttpOnly, Secure in production)
        Cookie refreshTokenCookie = new Cookie("refreshToken", tokens.getRefreshToken());
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false); // Set true in production with HTTPS
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge((int) authProperties.getJwt().getRefreshExpiration()); // auth.jwt.refreshExpiration (default 7d)
        response.addCookie(refreshTokenCookie);

        logger.debug("JWT tokens set in HttpOnly cookies");
    }

    /**
     * Clear JWT token cookies
     */
    private void clearTokenCookies(HttpServletResponse response) {
        Cookie accessTokenCookie = new Cookie("accessToken", null);
        accessTokenCookie.setHttpOnly(true);
        accessTokenCookie.setPath("/");
        accessTokenCookie.setMaxAge(0);
        response.addCookie(accessTokenCookie);

        Cookie refreshTokenCookie = new Cookie("refreshToken", null);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0);
        response.addCookie(refreshTokenCookie);

        logger.debug("JWT token cookies cleared");
    }

    /**
     * クライアントIPアドレスを取得
     * プロキシ経由の場合も考慮
     */
    private String getClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        // If multiple IPs, take the first one
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }
        return ip;
    }
}
