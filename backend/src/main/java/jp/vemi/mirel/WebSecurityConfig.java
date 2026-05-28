/*
 * Copyright(c) 2015-2024 mirelplatform.
 */
package jp.vemi.mirel;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jp.vemi.mirel.config.properties.AuthProperties;
import jp.vemi.mirel.config.properties.Mipla2SecurityProperties;
import jp.vemi.mirel.security.AuthenticationService;
import jp.vemi.mirel.security.CookieOrHeaderBearerTokenResolver;
import jp.vemi.mirel.security.jwt.JwtAuthoritiesConverter;
import jp.vemi.mirel.foundation.service.oauth2.CustomOAuth2UserService;
import jp.vemi.mirel.security.oauth2.OAuth2AuthenticationSuccessHandler;
import jp.vemi.mirel.security.oauth2.OAuth2AuthenticationFailureHandler;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.http.HttpStatus;

@lombok.extern.slf4j.Slf4j
@org.springframework.context.annotation.Configuration
@org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
public class WebSecurityConfig {

    @Autowired
    private AuthProperties authProperties;

    @Autowired
    private Mipla2SecurityProperties securityProperties;

    @Autowired
    private CustomOAuth2UserService customOAuth2UserService;

    @Autowired
    private OAuth2AuthenticationSuccessHandler oauth2SuccessHandler;

    @Autowired
    private OAuth2AuthenticationFailureHandler oauth2FailureHandler;

    @Autowired
    private JwtAuthoritiesConverter jwtAuthoritiesConverter;

    @Value("${cors.allowed-origins}")
    private String allowedOrigins;

    /**
     * Spring Securityのセキュリティフィルタチェーンを構成します。
     * CSRF保護、認可設定、認証方式の設定を行います。
     * 
     * <p>
     * このメソッドは以下の設定を行います：
     * <ul>
     * <li>CSRF保護の設定
     * <li>URLパターンごとのアクセス制御
     * <li>JWT認証またはフォーム認証の設定
     * </ul>
     *
     * @param http
     *            セキュリティ設定を構成するためのビルダー
     * @param authenticationService
     *            認証サービス（JWT認証またはフォーム認証の実装）
     * @return 構成されたセキュリティフィルタチェーン
     * @throws Exception
     *             セキュリティ設定の構成中にエラーが発生した場合
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
            AuthenticationService authenticationService) throws Exception {
        // データ初期化は DatabaseInitializer で行う（ここでは行わない）

        configureCors(http);
        configureCsrf(http);
        configureAuthorization(http);
        configureAuthentication(http, authenticationService);

        return http.build();
    }

    /**
     * CORS設定を行います。
     * 開発環境でフロントエンドからのAPIアクセスを許可します。
     *
     * @param http
     *            セキュリティ設定
     * @throws Exception
     *             設定中に例外が発生した場合
     */
    private void configureCors(HttpSecurity http) throws Exception {
        http.cors(cors -> cors.configurationSource(corsConfigurationSource()));
    }

    /**
     * CORS設定ソースを提供します。
     * 許可するオリジンは環境変数 CORS_ALLOWED_ORIGINS から取得します。
     * カンマ区切りで複数指定可能です。
     * 
     * @return CORS設定ソース
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 環境変数からカンマ区切りで許可オリジンを取得
        String[] origins = allowedOrigins.split(",");
        for (int i = 0; i < origins.length; i++) {
            origins[i] = origins[i].trim();
        }
        configuration.setAllowedOrigins(java.util.Arrays.asList(origins));

        configuration.setAllowedMethods(java.util.Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(java.util.Arrays.asList("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * CSRFの設定を行います。
     * securityPropertiesの設定に応じてCSRF保護の有効/無効を切り替えます。
     *
     * @param http
     *            セキュリティ設定
     * @throws Exception
     *             設定中に例外が発生した場合
     */
    // CodeQL [java/spring-disabled-csrf-protection] - CSRF protection is
    // configurable via Mipla2SecurityProperties
    // Default is ENABLED (csrfEnabled=true). Development mode can disable via
    // application-dev.yml for testing.
    // This is intentional design for flexibility in different environments.
    @SuppressWarnings({ "lgtm[java/spring-disabled-csrf-protection]" })
    private void configureCsrf(HttpSecurity http) throws Exception {
        // NOTE: CSRF protection is enabled by default
        // (Mipla2SecurityProperties.csrfEnabled=true)
        // Development environment can override this setting in application-dev.yml
        http.csrf(csrf -> {
            if (!securityProperties.isCsrfEnabled()) {
                csrf.disable();
            } else {
                csrf.ignoringRequestMatchers(
                        "/auth/login",
                        "/auth/refresh", // リフレッシュトークンはCSRF対象外とする場合が多いが、Cookie保存なら必要かも。ここでは一旦除外
                        "/api/auth/device/**", // デバイスフロー認証エンドポイント（CLI用）
                        "/api/bootstrap/**", // Bootstrap API（初期セットアップ用）
                        "/login/oauth2/code/**", // OAuth2コールバックをCSRF除外
                        "/oauth2/**") // OAuth2認証エンドポイントをCSRF除外
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(
                                new org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler());

                // CSRFトークンをCookieに書き込むためのフィルターを追加
                http.addFilterAfter(new CsrfCookieFilter(),
                        org.springframework.security.web.authentication.www.BasicAuthenticationFilter.class);
            }
        });
    }

    /**
     * CSRFトークンをCookieに書き込むためのフィルター。
     * Spring Security 6ではCSRFトークンの生成が遅延されるため、
     * 明示的にトークンを取得してCookieへの書き込みをトリガーする。
     */
    private static class CsrfCookieFilter extends org.springframework.web.filter.OncePerRequestFilter {
        @Override
        protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest request,
                jakarta.servlet.http.HttpServletResponse response, jakarta.servlet.FilterChain filterChain)
                throws jakarta.servlet.ServletException, java.io.IOException {
            org.springframework.security.web.csrf.CsrfToken csrfToken = (org.springframework.security.web.csrf.CsrfToken) request
                    .getAttribute(org.springframework.security.web.csrf.CsrfToken.class.getName());
            if (csrfToken != null) {
                // Render the token value to a cookie by causing the deferred token to be loaded
                csrfToken.getToken();
            }
            filterChain.doFilter(request, response);
        }
    }

    /**
     * 認可設定を行います。
     * securityPropertiesの設定に応じてAPIエンドポイントの認可要否を制御します。
     * 
     * <p>
     * <b>設計方針:</b> 未認証アクセスはデフォルトで401エラーを返す。
     * OAuth2 (GitHub) は /oauth2/authorization/github への明示的アクセスのみ有効。
     * 認証不要エンドポイントは明示的に permitAll() に追加する。
     * </p>
     *
     * @param http
     *            セキュリティ設定
     * @throws Exception
     *             設定中に例外が発生した場合
     */
    private void configureAuthorization(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authz -> {
            // 認証不要なAPIエンドポイント
            authz.requestMatchers(
                    "/auth/login",
                    "/auth/signup",
                    "/auth/otp/**",
                    "/auth/verify-setup-token", // アカウントセットアップトークン検証 (Issue #57)
                    "/auth/setup-account", // アカウントセットアップ（パスワード設定） (Issue #57)
                    "/auth/health",
                    "/auth/logout",
                    "/auth/check",
                    "/api/bootstrap/**" // Bootstrap API（初期セットアップ用）
            ).permitAll()

                    // デバイスフロー認証エンドポイント(CLI用)
                    .requestMatchers(
                            "/api/auth/device/code",
                            "/api/auth/device/token",
                            "/api/auth/device/verify")
                    .permitAll()

                    // OAuth2関連エンドポイント（Spring Securityが処理）
                    .requestMatchers(
                            "/login/oauth2/code/**", // OAuth2コールバック
                            "/oauth2/**", // OAuth2認証フロー
                            "/api/users/*/avatar" // アバター画像（公開）
            ).permitAll()

                    .requestMatchers("/actuator/**").permitAll() // Actuator endpoints for health checks
                    .requestMatchers("/v3/api-docs/**").permitAll() // OpenAPI JSON endpoint
                    .requestMatchers("/api-docs/**").permitAll() // OpenAPI JSON endpoint(Legacy)
                    .requestMatchers("/swagger-ui/**").permitAll() // Swagger UI static resources
                    .requestMatchers("/swagger-ui.html").permitAll() // Swagger UI HTML
                    .requestMatchers("/apps/mira/api/health").permitAll(); // Mira Health Check

            // refresh は Cookie の refreshToken で認証するため permitAll
            authz.requestMatchers("/auth/refresh").permitAll();

            // 認証必須エンドポイント
            authz.requestMatchers(
                    "/auth/me",
                    "/auth/switch-tenant").authenticated();

            // セキュリティ無効時は全てのAPIをパブリックに
            if (!securityProperties.isEnabled()) {
                authz.requestMatchers("/commons/**").permitAll()
                        .requestMatchers("/apps/*/api/**").permitAll()
                        .anyRequest().permitAll(); // ゲストモード：全てのリクエストを許可
            } else {
                // セキュリティ有効時のみ認証を要求
                authz.anyRequest().authenticated();
            }
        });
    }

    /**
     * 認証設定を行います。
     * authMethodの設定に応じてJWT認証またはフォーム認証を設定します。
     *
     * @param http
     *            セキュリティ設定
     * @param authenticationService
     *            認証サービス
     * @throws Exception
     *             設定中に例外が発生した場合
     */
    private void configureAuthentication(HttpSecurity http, AuthenticationService authenticationService)
            throws Exception {
        boolean jwtSupported = authenticationService.isJwtSupported();
        String authMethod = authProperties.getMethod();
        log.info("Configuring authentication: method={}, jwtSupported={}", authMethod, jwtSupported);
        if ("jwt".equals(authMethod) && jwtSupported) {
            log.info("Enabling JWT resource server configuration");

            // JWT の roles クレームを GrantedAuthority に変換するコンバーター
            JwtAuthenticationConverter jwtAuthConverter = new JwtAuthenticationConverter();
            jwtAuthConverter.setJwtGrantedAuthoritiesConverter(jwtAuthoritiesConverter);

            http.oauth2ResourceServer(oauth2 -> oauth2
                    .bearerTokenResolver(new CookieOrHeaderBearerTokenResolver()) // Cookie対応
                    .jwt(jwt -> jwt
                            .decoder(authenticationService.getJwtDecoder())
                            .jwtAuthenticationConverter(jwtAuthConverter)))
                    .sessionManagement(session -> session
                            .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        } else {
            log.info("Enabling session-based security context configuration");
            // JWT無効時はカスタム認証エンドポイント (/auth/otp/verify) を使用
            // formLogin()は使用せず、認証エンドポイントで直接SecurityContextを設定
            // 未認証時は401を返す（SPA構成のためリダイレクトしない）
            http.sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                    .securityContext(securityContext -> securityContext
                            .securityContextRepository(securityContextRepository())
                            .requireExplicitSave(false)) // SecurityContextHolderFilterが自動的にSecurityContextを保存
                    .exceptionHandling(exceptions -> exceptions
                            .authenticationEntryPoint((request, response, authException) -> {
                                // SPA構成: 未認証時は401を返す（302リダイレクトしない）
                                response.sendError(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED,
                                        "Unauthorized");
                            }));
        }

        // OAuth2ログイン設定（GitHub）
        // 重要: ユーザーが明示的に /oauth2/authorization/github にアクセスした場合のみOAuth2フローを開始
        // その他の未認証アクセスは401を返す（OAuth2にリダイレクトしない）
        http.oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo
                        .userService(customOAuth2UserService))
                .successHandler(oauth2SuccessHandler)
                .failureHandler(oauth2FailureHandler));

        // 未認証アクセス時のハンドリング
        // デフォルトで401を返す（OAuth2リダイレクトを防ぐ）
        // OAuth2は /oauth2/authorization/github への明示的アクセスのみ有効
        http.exceptionHandling(handling -> handling
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)));
    }

    /**
     * デフォルトのユーザー詳細サービスを提供します。
     * 開発環境用の基本認証ユーザーを設定します。
     *
     * @param passwordEncoder
     *            パスワードエンコーダー
     * @return UserDetailsService
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        UserDetails user = User.builder()
                .username("dev")
                .password(passwordEncoder.encode("dev"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // BCryptPasswordEncoder を直接使用（プレフィックス不要）
        return new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
    }

    /**
     * SecurityContextRepository Bean.
     * OTP認証などのカスタム認証でセッションにSecurityContextを保存・復元するために使用します。
     * 
     * Spring Security 6の公式推奨に従い、DelegatingSecurityContextRepositoryを使用。
     * これにより、RequestAttributeSecurityContextRepository（リクエスト属性）と
     * HttpSessionSecurityContextRepository（HTTPセッション）両方でSecurityContextを管理。
     * 
     * @return DelegatingSecurityContextRepository
     */
    @Bean
    public org.springframework.security.web.context.SecurityContextRepository securityContextRepository() {
        return new org.springframework.security.web.context.DelegatingSecurityContextRepository(
                new org.springframework.security.web.context.RequestAttributeSecurityContextRepository(),
                new org.springframework.security.web.context.HttpSessionSecurityContextRepository());
    }

    @Bean
    public AuthenticationManager authenticationManager(HttpSecurity http, PasswordEncoder passwordEncoder)
            throws Exception {
        AuthenticationManagerBuilder authenticationManagerBuilder = http
                .getSharedObject(AuthenticationManagerBuilder.class);
        authenticationManagerBuilder.inMemoryAuthentication()
                .withUser("dev").password(passwordEncoder.encode("dev")).roles("USER");
        return authenticationManagerBuilder.build();
    }
}
