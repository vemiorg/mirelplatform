/*
 * Copyright(c) 2015-2025 mirelplatform.
 */
package jp.vemi.mirel.foundation.web.api.auth.service;

import jp.vemi.mirel.foundation.abst.dao.entity.*;
import jp.vemi.mirel.foundation.abst.dao.entity.ApplicationLicense.LicenseTier;
import jp.vemi.mirel.foundation.abst.dao.entity.ApplicationLicense.SubjectType;
import jp.vemi.mirel.foundation.abst.dao.repository.*;
import jp.vemi.mirel.foundation.exception.EmailNotVerifiedException;
import jp.vemi.mirel.foundation.web.api.auth.dto.*;
import jp.vemi.mirel.security.jwt.JwtService;
import jp.vemi.framework.util.SanitizeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.util.Pair;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Refresh token の再利用検知時にスローされる例外。
 * 全トークン revoke をコミットする必要があるため、
 * この例外では @Transactional のロールバックを抑制する。
 */
class RefreshTokenReuseException extends jp.vemi.framework.exeption.MirelValidationException {
    RefreshTokenReuseException(String message) {
        super(message);
    }
}

/**
 * 認証サービス実装.
 */
@org.springframework.stereotype.Service
@lombok.extern.slf4j.Slf4j
public class AuthenticationServiceImpl {

    // OTP/OAuth2ユーザー用の事前計算済みダミーパスワードハッシュ（bcrypt）
    // パスワードレス認証のユーザーはこのハッシュを使用し、実際の認証では使用されない
    private static final String DUMMY_PASSWORD_HASH = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy";

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SystemUserRepository systemUserRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private UserTenantRepository userTenantRepository;

    @Autowired
    private ApplicationLicenseRepository licenseRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired(required = false)
    private JwtService jwtService;

    @Autowired
    private jp.vemi.mirel.config.properties.AuthProperties authProperties;

    @Autowired
    private jp.vemi.mirel.foundation.service.OtpService otpService;

    @Autowired
    private jp.vemi.mirel.foundation.abst.dao.repository.OtpTokenRepository otpTokenRepository;

    @Autowired
    private jp.vemi.mirel.foundation.security.audit.AuthEventLogger authEventLogger;

    /**
     * セットアップトークン検証の共通ロジック
     * 
     * @param token
     *            セットアップトークン
     * @return 検証済みトークンとSystemUserのペア
     * @throws RuntimeException
     *             トークンが無効または期限切れの場合
     */
    private Pair<OtpToken, SystemUser> validateSetupToken(String token) {
        // トークン検証
        OtpToken otpToken = otpTokenRepository.findByMagicLinkTokenAndPurposeAndIsVerifiedFalse(token, "ACCOUNT_SETUP")
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelValidationException("無効または期限切れのセットアップリンクです"));

        // 有効期限チェック
        if (otpToken.getExpiresAt().isBefore(java.time.LocalDateTime.now())) {
            throw new jp.vemi.framework.exeption.MirelValidationException("セットアップリンクの有効期限が切れています");
        }

        // SystemUser取得
        SystemUser systemUser = systemUserRepository.findById(otpToken.getSystemUserId())
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelResourceNotFoundException("ユーザーが見つかりません"));

        return Pair.of(otpToken, systemUser);
    }

    /**
     * アカウントセットアップトークンを検証
     * 
     * @param token
     *            セットアップトークン
     * @return ユーザー情報（email, username）
     * @throws RuntimeException
     *             トークンが無効または期限切れの場合
     */
    @Transactional(readOnly = true)
    public VerifySetupTokenResponse verifyAccountSetupToken(String token) {
        log.info("Verifying account setup token");

        Pair<OtpToken, SystemUser> validated = validateSetupToken(token);
        SystemUser systemUser = validated.getSecond();

        log.info("Setup token verified for user: {}", systemUser.getEmail());

        return VerifySetupTokenResponse.builder()
                .email(systemUser.getEmail())
                .username(systemUser.getUsername())
                .build();
    }

    /**
     * アカウントセットアップ（パスワード設定）
     * 
     * @param token
     *            セットアップトークン
     * @param newPassword
     *            新しいパスワード
     * @throws RuntimeException
     *             トークンが無効、期限切れ、またはパスワード設定に失敗した場合
     */
    @Transactional
    public void setupAccount(String token, String newPassword) {
        log.info("Setting up account with setup token");

        // トークン検証（共通ロジック使用）
        Pair<OtpToken, SystemUser> validated = validateSetupToken(token);
        OtpToken otpToken = validated.getFirst();
        SystemUser systemUser = validated.getSecond();

        // パスワードハッシュ化
        String passwordHash = passwordEncoder.encode(newPassword);

        // SystemUser更新（パスワード設定 + メール検証完了）
        systemUser.setPasswordHash(passwordHash);
        systemUser.setEmailVerified(true);
        systemUserRepository.save(systemUser);

        // User更新（メール検証完了）
        userRepository.findBySystemUserId(systemUser.getId()).ifPresent(user -> {
            user.setEmailVerified(true);
            userRepository.save(user);
            log.info("User profile updated: email verified for userId={}", user.getUserId());
        });

        // トークン無効化
        otpToken.setIsVerified(true);
        otpToken.setVerifiedAt(java.time.LocalDateTime.now());
        otpTokenRepository.save(otpToken);

        log.info("Account setup completed for user: {}", systemUser.getEmail());
    }

    /**
     * ログイン処理
     */
    @Transactional
    public AuthenticationResponse login(LoginRequest request) {
        log.info("Login attempt for username or email: {}", SanitizeUtil.forLog(request.getUsernameOrEmail()));

        // SystemUserでusernameまたはemailを検索
        SystemUser systemUser = systemUserRepository.findByUsername(request.getUsernameOrEmail())
                .or(() -> systemUserRepository.findByEmail(request.getUsernameOrEmail()))
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelValidationException(
                        "Invalid username/email or password"));

        // アクティブチェック
        if (systemUser.getIsActive() == null || !systemUser.getIsActive()) {
            throw new jp.vemi.framework.exeption.MirelValidationException("User account is not active");
        }

        // アカウントロックチェック
        if (systemUser.getAccountLocked() != null && systemUser.getAccountLocked()) {
            throw new jp.vemi.framework.exeption.MirelValidationException("User account is locked");
        }

        // パスワード検証
        if (!passwordEncoder.matches(request.getPassword(), systemUser.getPasswordHash())) {
            log.warn("Invalid password for user: {}", SanitizeUtil.forLog(request.getUsernameOrEmail()));

            // ログイン失敗回数をインクリメント
            Integer failedAttempts = systemUser.getFailedLoginAttempts() == null ? 0
                    : systemUser.getFailedLoginAttempts();
            systemUser.setFailedLoginAttempts(failedAttempts + 1);

            // 5回失敗でアカウントロック
            if (failedAttempts + 1 >= 5) {
                systemUser.setAccountLocked(true);
                log.warn("Account locked due to multiple failed login attempts: {}",
                        SanitizeUtil.forLog(request.getUsernameOrEmail()));
                authEventLogger.logAccountLocked(SanitizeUtil.forLog(request.getUsernameOrEmail()),
                        SanitizeUtil.forLog(request.getIpAddress()));
            }

            systemUserRepository.save(systemUser);
            authEventLogger.logLoginFailure(SanitizeUtil.forLog(request.getUsernameOrEmail()), "Invalid password",
                    SanitizeUtil.forLog(request.getIpAddress()), SanitizeUtil.forLog(request.getUserAgent()));
            throw new jp.vemi.framework.exeption.MirelValidationException("Invalid username/email or password");
        }

        // メールアドレス検証チェック
        if (systemUser.getEmailVerified() == null || !systemUser.getEmailVerified()) {
            log.warn("Login attempt with unverified email: {}", systemUser.getEmail());

            // 管理者作成ユーザーの場合、自動的に検証メール送信
            if (Boolean.TRUE.equals(systemUser.getCreatedByAdmin())) {
                log.info("Auto-sending verification email for admin-created user: {}", systemUser.getEmail());
                try {
                    String ipAddress = request.getIpAddress() != null ? request.getIpAddress() : "unknown";
                    String userAgent = request.getUserAgent() != null ? request.getUserAgent() : "unknown";
                    otpService.requestOtp(
                            systemUser.getEmail(),
                            "EMAIL_VERIFICATION",
                            ipAddress,
                            userAgent);
                } catch (Exception e) {
                    log.error("Failed to send verification email: {}", systemUser.getEmail(), e);
                    // メール送信失敗でもログイン拒否（エラー詳細は記録するがユーザーには公開しない）
                }
                throw new EmailNotVerifiedException(
                        "メールアドレスが未検証です。検証コードを送信しました。受信ボックスを確認してください。",
                        systemUser.getEmail());
            } else {
                // 通常のユーザーの場合は検証メール送信なし
                throw new EmailNotVerifiedException(
                        "メールアドレスが未検証です。受信ボックスを確認してください。",
                        systemUser.getEmail());
            }
        }

        // ログイン成功：失敗回数リセット
        systemUser.setFailedLoginAttempts(0);
        systemUserRepository.save(systemUser);

        // Userエンティティを取得（ApplicationデータにアクセスするためにsystemUserIdで検索）
        User user = userRepository.findBySystemUserId(systemUser.getId())
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelSystemException("User profile not found"));

        // 最終ログイン時刻更新
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        // テナント解決
        Tenant tenant = resolveTenant(user, request.getTenantId());

        // トークン生成（JWT有効な場合のみ）
        String accessToken;
        boolean isJwtEnabled = authProperties.getJwt().isEnabled();
        if (isJwtEnabled && jwtService != null) {
            accessToken = jwtService.generateToken(
                    new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                            user.getUserId(), null, buildAuthoritiesFromUser(user)));
        } else {
            accessToken = "session-based-auth-token";
            log.warn("JWT is disabled. Using session-based authentication placeholder.");
        }

        // RefreshToken作成（rememberMe対応）
        boolean rememberMe = request.getRememberMe() != null && request.getRememberMe();
        RefreshToken refreshToken = createRefreshToken(user, rememberMe);

        // 有効ライセンス取得
        List<ApplicationLicense> licenses = licenseRepository.findEffectiveLicenses(
                user.getUserId(), tenant != null ? tenant.getTenantId() : null, Instant.now());

        log.info("Login successful for user: {}", user.getUserId());
        authEventLogger.logLoginSuccess(user.getUserId(), user.getUsername(),
                request.getIpAddress(), request.getUserAgent());

        return buildAuthenticationResponse(user, tenant, accessToken, refreshToken.getTokenHash(), licenses);
    }

    /**
     * ユーザー指定ログイン処理 (OTP等から利用)
     */
    @Transactional
    public AuthenticationResponse loginWithUser(User user) {
        log.info("Login with user object: {}", user.getUserId());

        // 最終ログイン時刻更新
        user.setLastLoginAt(Instant.now());
        userRepository.save(user);

        // テナント解決
        Tenant tenant = resolveTenant(user, null);

        // トークン生成（JWT有効な場合のみ）
        String accessToken;
        boolean isJwtEnabled = authProperties.getJwt().isEnabled();
        if (isJwtEnabled && jwtService != null) {
            accessToken = jwtService.generateToken(
                    new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                            user.getUserId(), null, buildAuthoritiesFromUser(user)));
        } else {
            accessToken = "session-based-auth-token";
            log.warn("JWT is disabled. Using session-based authentication placeholder.");
        }

        // RefreshToken作成
        RefreshToken refreshToken = createRefreshToken(user);

        // 有効ライセンス取得
        List<ApplicationLicense> licenses = licenseRepository.findEffectiveLicenses(
                user.getUserId(), tenant != null ? tenant.getTenantId() : null, Instant.now());

        log.info("Login successful for user: {}", user.getUserId());

        return buildAuthenticationResponse(user, tenant, accessToken, refreshToken.getTokenHash(), licenses);
    }

    /**
     * サインアップ処理
     */
    @Transactional
    public AuthenticationResponse signup(SignupRequest request) {
        log.info("Signup attempt for username: {}, email: {}", SanitizeUtil.forLog(request.getUsername()),
                SanitizeUtil.forLog(request.getEmail()));

        // ユーザー名重複チェック
        if (systemUserRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new jp.vemi.framework.exeption.MirelValidationException("Username already exists");
        }

        // メール重複チェック
        if (systemUserRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new jp.vemi.framework.exeption.MirelValidationException("Email already exists");
        }

        // SystemUser作成
        SystemUser systemUser = new SystemUser();
        systemUser.setId(UUID.randomUUID());
        systemUser.setUsername(request.getUsername());
        systemUser.setEmail(request.getEmail());
        systemUser.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        systemUser.setIsActive(true);
        systemUser.setEmailVerified(false);
        systemUser = systemUserRepository.save(systemUser);

        // User作成（Applicationレベル）
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setSystemUserId(systemUser.getId());
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setDisplayName(request.getDisplayName());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setIsActive(true);
        user.setEmailVerified(false);
        user.setRoles("USER");
        user = userRepository.save(user);

        // デフォルトテナント割り当て（共通ヘルパーメソッド使用）
        assignDefaultTenantToUser(user);

        // デフォルトライセンス付与（共通ヘルパーメソッド使用）
        ApplicationLicense license = grantDefaultLicense(user);

        // トークン生成（共通ヘルパーメソッド使用）
        TokenDto tokens = generateAuthTokens(user);

        // テナント取得
        Tenant tenant = tenantRepository.findById(user.getTenantId()).orElse(null);

        log.info("Signup successful for user: {}", user.getUserId());

        return buildAuthenticationResponse(user, tenant, tokens.getAccessToken(),
                tokens.getRefreshToken(), List.of(license));
    }

    /**
     * OAuth2サインアップ処理
     */
    @Transactional
    public AuthenticationResponse signupWithOAuth2(OAuth2SignupRequest request, String systemUserIdStr) {
        log.info("OAuth2 signup attempt for username: {}, systemUserId: {}", SanitizeUtil.forLog(request.getUsername()),
                SanitizeUtil.forLog(systemUserIdStr));

        UUID systemUserId = UUID.fromString(systemUserIdStr);
        SystemUser systemUser = systemUserRepository.findById(systemUserId)
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelValidationException("System user not found"));

        // ユーザー名重複チェック
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new jp.vemi.framework.exeption.MirelValidationException("Username already exists");
        }

        // User作成
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setSystemUserId(systemUser.getId());
        user.setUsername(request.getUsername());
        user.setEmail(systemUser.getEmail()); // SystemUserのメールを使用
        user.setDisplayName(request.getDisplayName());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPasswordHash(DUMMY_PASSWORD_HASH); // 事前計算済みダミーハッシュを使用
        user.setIsActive(true);
        user.setEmailVerified(systemUser.getEmailVerified());
        user.setRoles("USER");
        user = userRepository.save(user);

        // デフォルトテナント割り当て（共通ヘルパーメソッド使用）
        assignDefaultTenantToUser(user);

        // デフォルトライセンス付与（共通ヘルパーメソッド使用）
        ApplicationLicense license = grantDefaultLicense(user);

        // トークン生成（共通ヘルパーメソッド使用）
        TokenDto tokens = generateAuthTokens(user);

        // テナント取得
        Tenant tenant = tenantRepository.findById(user.getTenantId()).orElse(null);

        log.info("OAuth2 signup successful for user: {}", user.getUserId());

        return buildAuthenticationResponse(user, tenant, tokens.getAccessToken(),
                tokens.getRefreshToken(), List.of(license));
    }

    /**
     * OTPベースサインアップ処理
     * メールアドレス検証済みのユーザーを作成し、ログイン状態にする
     */
    @Transactional
    public AuthenticationResponse signupWithOtp(jp.vemi.mirel.foundation.web.api.auth.dto.OtpSignupRequest request) {
        log.info("OTP-based signup attempt for username: {}, email: {}", SanitizeUtil.forLog(request.getUsername()),
                SanitizeUtil.forLog(request.getEmail()));

        // ユーザー名重複チェック
        if (systemUserRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new RuntimeException("Username already exists");
        }

        // メール重複チェック
        if (systemUserRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new RuntimeException("Email already exists");
        }

        // SystemUser作成（パスワードはプレースホルダー）
        SystemUser systemUser = new SystemUser();
        systemUser.setId(UUID.randomUUID());
        systemUser.setUsername(request.getUsername());
        systemUser.setEmail(request.getEmail());
        systemUser.setPasswordHash(DUMMY_PASSWORD_HASH); // 事前計算済みダミーハッシュを使用
        systemUser.setIsActive(true);
        systemUser.setEmailVerified(true); // OTP検証済み
        systemUser = systemUserRepository.save(systemUser);

        // User作成（Applicationレベル）
        User user = new User();
        user.setUserId(UUID.randomUUID().toString());
        user.setSystemUserId(systemUser.getId());
        user.setUsername(request.getUsername());
        user.setEmail(request.getEmail());
        user.setDisplayName(request.getDisplayName());
        user.setFirstName(request.getFirstName());
        user.setLastName(request.getLastName());
        user.setPasswordHash(DUMMY_PASSWORD_HASH); // 事前計算済みダミーハッシュを使用
        user.setIsActive(true);
        user.setEmailVerified(true); // OTP検証済み
        user.setRoles("USER");
        user.setLastLoginAt(Instant.now()); // 最終ログイン時刻を設定（初回サインアップ時にも記録）
        user = userRepository.save(user);

        // デフォルトテナント割り当て（共通ヘルパーメソッド使用）
        assignDefaultTenantToUser(user);

        // デフォルトライセンス付与（共通ヘルパーメソッド使用）
        ApplicationLicense license = grantDefaultLicense(user);

        // トークン生成（共通ヘルパーメソッド使用）
        TokenDto tokens = generateAuthTokens(user);

        // テナント取得
        Tenant tenant = tenantRepository.findById(user.getTenantId()).orElse(null);

        log.info("OTP-based signup successful for user: {}", user.getUserId());

        return buildAuthenticationResponse(user, tenant, tokens.getAccessToken(),
                tokens.getRefreshToken(), List.of(license));
    }

    /**
     * トークンリフレッシュ（Token Rotation + 再利用検知 + Sliding Expiry）
     *
     * <ol>
     *   <li>提示された refresh token を検証</li>
     *   <li>再利用検知: revoked 済み（= 既に rotation 済み）のトークンが再提示された場合、
     *       トークン盗難とみなしユーザーの全トークンを revoke</li>
     *   <li>旧トークンを revoke し、新トークンを発行（rotation）</li>
     *   <li>新トークンの有効期限は now + refreshExpiration（sliding expiry）</li>
     * </ol>
     */
    @Transactional(noRollbackFor = RefreshTokenReuseException.class)
    public AuthenticationResponse refresh(RefreshTokenRequest request) {
        boolean isJwtEnabled = authProperties.getJwt().isEnabled();
        if (!isJwtEnabled || jwtService == null) {
            throw new IllegalStateException("JWT is disabled. Refresh token not supported.");
        }
        log.info("Token refresh attempt");

        // RefreshToken 検索
        String tokenHash = hashToken(request.getRefreshToken());
        RefreshToken oldRefreshToken = refreshTokenRepository.findByTokenHash(tokenHash)
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelValidationException("Invalid refresh token"));

        // ── 再利用検知 ──
        // revoked 済みトークンが再提示された → 盗難の可能性 → 全トークン revoke
        if (oldRefreshToken.getRevokedAt() != null) {
            log.warn("Refresh token reuse detected for user: {}. Revoking all tokens.", oldRefreshToken.getUserId());
            authEventLogger.logLoginFailure(oldRefreshToken.getUserId(),
                    "Refresh token reuse detected (possible theft)", "unknown", "unknown");
            revokeAllUserTokens(oldRefreshToken.getUserId());
            throw new RefreshTokenReuseException(
                    "Refresh token reuse detected. All sessions have been revoked for security.");
        }

        // 通常の有効性チェック（期限切れ, deleteFlag）
        if (!oldRefreshToken.isValid()) {
            throw new jp.vemi.framework.exeption.MirelValidationException("Refresh token is expired or revoked");
        }

        // ユーザー取得
        User user = userRepository.findById(oldRefreshToken.getUserId())
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelSystemException("User not found"));

        // テナント取得
        Tenant tenant = user.getTenantId() != null ? tenantRepository.findById(user.getTenantId()).orElse(null) : null;

        // ── Token Rotation: 新トークン発行 + 旧トークン revoke ──
        RefreshToken newRefreshToken = createRefreshToken(user);  // sliding expiry: expiresAt = now + refreshExpiration

        // 旧トークンを revoke し、後継を記録（再利用検知チェーン用）
        oldRefreshToken.setRevokedAt(Instant.now());
        oldRefreshToken.setReplacedByTokenHash(hashToken(newRefreshToken.getTokenHash())); // tokenHash は一時的に tokenValue を保持
        refreshTokenRepository.save(oldRefreshToken);

        // ── 新しいアクセストークン生成（権限を正しく載せる） ──
        String accessToken = jwtService.generateToken(
                new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        user.getUserId(), null, buildAuthoritiesFromUser(user)));

        // 有効ライセンス取得
        List<ApplicationLicense> licenses = licenseRepository.findEffectiveLicenses(
                user.getUserId(), tenant != null ? tenant.getTenantId() : null, Instant.now());

        log.info("Token refresh successful (rotation) for user: {}", user.getUserId());

        return buildAuthenticationResponse(user, tenant, accessToken, newRefreshToken.getTokenHash(), licenses);
    }

    /**
     * ユーザーの全有効トークンを revoke（再利用検知時）
     */
    private void revokeAllUserTokens(String userId) {
        List<RefreshToken> activeTokens = refreshTokenRepository.findAllActiveByUserId(userId);
        Instant now = Instant.now();
        for (RefreshToken token : activeTokens) {
            token.setRevokedAt(now);
            refreshTokenRepository.save(token);
        }
        log.info("Revoked {} active tokens for user: {}", activeTokens.size(), userId);
    }

    /**
     * ログアウト
     */
    @Transactional
    public void logout(String refreshToken) {
        log.info("Logout attempt");

        if (refreshToken != null && !refreshToken.isEmpty()) {
            String tokenHash = hashToken(refreshToken);
            refreshTokenRepository.findByTokenHash(tokenHash).ifPresent(token -> {
                token.setRevokedAt(Instant.now());
                refreshTokenRepository.save(token);
                log.info("Refresh token revoked for user: {}", token.getUserId());
            });
        }
    }

    /**
     * 検証メール再送
     * 
     * @param email
     *            メールアドレス
     * @param ipAddress
     *            リクエスト元IPアドレス
     * @param userAgent
     *            User-Agent
     */
    @Transactional
    public void resendVerificationEmail(String email, String ipAddress, String userAgent) {
        log.info("Resend verification email request: email={}", SanitizeUtil.forLog(email));

        // ユーザーが存在しなくてもエラーにしない（列挙攻撃対策）
        SystemUser systemUser = systemUserRepository.findByEmail(email).orElse(null);

        if (systemUser != null && !Boolean.TRUE.equals(systemUser.getEmailVerified())) {
            // 既存の OTP 基盤を活用
            try {
                otpService.requestOtp(email, "EMAIL_VERIFICATION", ipAddress, userAgent);
                log.info("Verification email sent: email={}", SanitizeUtil.forLog(email));
            } catch (Exception e) {
                log.error("Failed to send verification email: email={}", SanitizeUtil.forLog(email), e);
                // エラーを外部に公開しない（セキュリティ）
            }
        } else {
            // ユーザーが存在しない、または既に検証済みの場合でもログのみ
            log.info("Verification email request ignored: email={} (not found or already verified)",
                    SanitizeUtil.forLog(email));
        }
    }

    /**
     * テナント切替
     */
    @Transactional
    public UserContextDto switchTenant(String userId, String tenantId) {
        log.info("Tenant switch attempt: user={}, tenant={}", SanitizeUtil.forLog(userId),
                SanitizeUtil.forLog(tenantId));

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelSystemException("User not found"));

        // ユーザーがテナントに所属しているか確認
        UserTenant userTenant = userTenantRepository.findByUserIdAndTenantId(userId, tenantId)
                .orElseThrow(() -> new RuntimeException("User is not a member of this tenant"));

        // デフォルトテナント更新
        // まず全てのUserTenantのisDefaultをfalseに
        userTenantRepository.findByUserId(userId).forEach(ut -> {
            ut.setIsDefault(false);
            userTenantRepository.save(ut);
        });

        // 選択したテナントをデフォルトに
        userTenant.setIsDefault(true);
        userTenantRepository.save(userTenant);

        // User のtenantIdも更新
        user.setTenantId(tenantId);
        userRepository.save(user);

        // Tenant取得
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new jp.vemi.framework.exeption.MirelResourceNotFoundException("Tenant not found"));

        log.info("Tenant switch successful: user={}, new tenant={}", SanitizeUtil.forLog(userId),
                SanitizeUtil.forLog(tenantId));

        return UserContextDto.builder()
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
                .currentTenant(TenantContextDto.builder()
                        .tenantId(tenant.getTenantId())
                        .tenantName(tenant.getTenantName())
                        .displayName(tenant.getDisplayName())
                        .build())
                .build();
    }

    /**
     * テナント解決
     */
    private Tenant resolveTenant(User user, String requestedTenantId) {
        String tenantId = requestedTenantId != null ? requestedTenantId : user.getTenantId();

        if (tenantId == null) {
            // デフォルトテナント取得
            UserTenant defaultUserTenant = userTenantRepository.findDefaultByUserId(user.getUserId())
                    .orElse(null);
            if (defaultUserTenant != null) {
                tenantId = defaultUserTenant.getTenantId();
            } else {
                tenantId = "default";
            }
        }

        return tenantRepository.findById(tenantId).orElse(null);
    }

    /**
     * デフォルトテナント取得または作成
     */
    private Tenant getOrCreateDefaultTenant() {
        return tenantRepository.findById("default").orElseGet(() -> {
            Tenant tenant = new Tenant();
            tenant.setTenantId("default");
            tenant.setTenantName("Default Workspace");
            tenant.setDisplayName("Default Workspace");
            tenant.setIsActive(true);
            return tenantRepository.save(tenant);
        });
    }

    /**
     * RefreshToken作成
     *
     * @param user
     *            ユーザー
     * @param rememberMe
     *            ログイン状態を永続化するか
     *            true: auth.jwt.rememberMeRefreshExpiration (デフォルト90日)
     *            false: auth.jwt.refreshExpiration (デフォルト7日)
     */
    private RefreshToken createRefreshToken(User user, boolean rememberMe) {
        String tokenValue = UUID.randomUUID().toString();
        String tokenHash = hashToken(tokenValue);

        // AuthProperties からリフレッシュトークン有効期限を取得
        long expirationSeconds = rememberMe
                ? authProperties.getJwt().getRememberMeRefreshExpiration()
                : authProperties.getJwt().getRefreshExpiration();

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(user.getUserId());
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setExpiresAt(Instant.now().plusSeconds(expirationSeconds));
        refreshToken.setDeviceInfo("web");
        refreshTokenRepository.save(refreshToken);

        // tokenHashにtokenValueを一時的に保存（レスポンス用）
        refreshToken.setTokenHash(tokenValue);
        return refreshToken;
    }

    /**
     * RefreshToken作成（デフォルト: 非rememberMe）
     * 後方互換性のためのオーバーロード
     */
    private RefreshToken createRefreshToken(User user) {
        return createRefreshToken(user, false);
    }

    /**
     * トークンハッシュ生成
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1)
                    hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new jp.vemi.framework.exeption.MirelSystemException("Failed to hash token", e);
        }
    }

    /**
     * AuthenticationResponse構築
     */
    private AuthenticationResponse buildAuthenticationResponse(User user, Tenant tenant,
            String accessToken, String refreshToken, List<ApplicationLicense> licenses) {

        return AuthenticationResponse.builder()
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
                .tokens(TokenDto.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .expiresIn(authProperties.getJwt().getExpiration())
                        .build())
                .currentTenant(tenant != null ? TenantContextDto.builder()
                        .tenantId(tenant.getTenantId())
                        .tenantName(tenant.getTenantName())
                        .displayName(tenant.getDisplayName())
                        .build() : null)
                .build();
    }

    /**
     * ユーザーのロール文字列からSpring Security権限リストを生成
     * ロールはカンマ(,)またはパイプ(|)で区切られた文字列
     * 
     * @param user
     *            ユーザー
     * @return 権限リスト
     */
    private List<SimpleGrantedAuthority> buildAuthoritiesFromUser(User user) {
        String roles = user.getRoles();
        if (roles == null || roles.isBlank()) {
            // デフォルトでUSERロールを付与
            return Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"));
        }

        // カンマまたはパイプで区切り
        return Arrays.stream(roles.split("[,|]"))
                .map(String::trim)
                .filter(role -> !role.isEmpty())
                .map(role -> {
                    // ROLE_ プレフィックスがない場合は追加
                    if (!role.startsWith("ROLE_")) {
                        return new SimpleGrantedAuthority("ROLE_" + role.toUpperCase());
                    }
                    return new SimpleGrantedAuthority(role.toUpperCase());
                })
                .collect(Collectors.toList());
    }

    /**
     * デフォルトテナントをユーザーに割り当て
     * すべてのサインアップメソッドで共通の処理を統一
     */
    private void assignDefaultTenantToUser(User user) {
        // デフォルトテナント作成または割り当て
        Tenant defaultTenant = getOrCreateDefaultTenant();
        user.setTenantId(defaultTenant.getTenantId());
        userRepository.save(user);

        // UserTenant作成
        UserTenant userTenant = new UserTenant();
        userTenant.setUserId(user.getUserId());
        userTenant.setTenantId(defaultTenant.getTenantId());
        userTenant.setRoleInTenant("MEMBER");
        userTenant.setIsDefault(true);
        userTenantRepository.save(userTenant);
    }

    /**
     * デフォルトライセンスをユーザーに付与
     */
    private ApplicationLicense grantDefaultLicense(User user) {
        ApplicationLicense license = new ApplicationLicense();
        license.setSubjectType(SubjectType.USER);
        license.setSubjectId(user.getUserId());
        license.setApplicationId("promarker");
        license.setTier(LicenseTier.FREE);
        license.setGrantedBy("system");
        licenseRepository.save(license);
        return license;
    }

    /**
     * JWTアクセストークンを生成
     * すべてのサインアップメソッドで一貫したトークン生成を保証
     */
    private TokenDto generateAuthTokens(User user) {
        String accessToken;
        boolean isJwtEnabled = authProperties.getJwt().isEnabled();

        if (isJwtEnabled && jwtService != null) {
            // ユーザーの権限を取得して使用
            List<SimpleGrantedAuthority> authorities = buildAuthoritiesFromUser(user);
            accessToken = jwtService.generateToken(
                    new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                            user.getUserId(), null, authorities));
        } else {
            accessToken = "session-based-auth-token";
            log.warn("JWT is disabled. Using session-based authentication placeholder.");
        }

        RefreshToken refreshToken = createRefreshToken(user);

        TokenDto tokens = new TokenDto();
        tokens.setAccessToken(accessToken);
        tokens.setRefreshToken(refreshToken.getTokenHash()); // 実際はtokenValue
        tokens.setExpiresIn(3600L); // 1 hour (Long type)

        return tokens;
    }
}
