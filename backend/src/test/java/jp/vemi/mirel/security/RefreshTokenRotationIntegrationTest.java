package jp.vemi.mirel.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.UUID;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.ai.chat.model.ChatModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.Cookie;
import jp.vemi.mirel.foundation.abst.dao.entity.RefreshToken;
import jp.vemi.mirel.foundation.abst.dao.entity.SystemUser;
import jp.vemi.mirel.foundation.abst.dao.entity.User;
import jp.vemi.mirel.foundation.abst.dao.repository.RefreshTokenRepository;
import jp.vemi.mirel.foundation.abst.dao.repository.SystemUserRepository;
import jp.vemi.mirel.foundation.abst.dao.repository.UserRepository;
// VectorStore は e2e プロファイル (Postgres + pgvector) で動作するため mock 不要

/**
 * Refresh Token Rotation 統合テスト.
 *
 * <ul>
 *   <li>P0-1: Cookie からの refresh token 読み取り</li>
 *   <li>P0-2: RT 寿命が AuthProperties と一致</li>
 *   <li>P1-3: Token rotation（旧 RT revoke + 新 RT 発行）</li>
 *   <li>P1-3: 再利用検知（revoked RT 再提示 → 全 RT revoke）</li>
 *   <li>P1-4: Sliding expiry（refresh のたびに新 RT の期限が延長）</li>
 *   <li>P1-6: refresh 後の JWT に権限（roles）が含まれること</li>
 * </ul>
 */
@SpringBootTest(properties = {
        "spring.main.allow-bean-definition-overriding=true",
        "auth.method=jwt",
        "auth.jwt.enabled=true",
        "auth.jwt.secret=verylongsecretkeythatisatleast32byteslongforsecurityreasons",
        "auth.jwt.expiration=3600",
        "auth.jwt.refresh-expiration=604800",
        "mipla2.security.api.csrf-enabled=false",
        "mira.ai.provider=mock",
        "mira.ai.mock.enabled=true",
        // Docker Compose dev 環境の Postgres に接続
        "spring.datasource.url=jdbc:postgresql://localhost:5432/mirelplatform",
        "spring.datasource.username=mirel",
        "spring.datasource.password=mirel"
})
@AutoConfigureMockMvc
@ActiveProfiles("e2e")
@DisplayName("Refresh Token Rotation 統合テスト")
public class RefreshTokenRotationIntegrationTest {

    @TestConfiguration
    static class TestConfig {
        @Bean
        @Primary
        ChatModel mockChatModel() {
            return mock(ChatModel.class);
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SystemUserRepository systemUserRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String EMAIL = "refresh-test@example.com";
    private static final String USER_ID = "user-refresh-test-001";
    private static final String PASSWORD = "password123";

    @BeforeEach
    void setUp() {
        // 既存テストデータを削除
        userRepository.findById(USER_ID).ifPresent(u -> userRepository.delete(u));
        systemUserRepository.findByEmail(EMAIL).ifPresent(su -> systemUserRepository.delete(su));
        // テストユーザーの既存リフレッシュトークンも削除
        refreshTokenRepository.findValidTokensByUserId(USER_ID, Instant.EPOCH)
                .forEach(rt -> refreshTokenRepository.delete(rt));

        // SystemUser 作成
        SystemUser su = new SystemUser();
        su.setId(UUID.fromString("550e8400-e29b-41d4-a716-446655440099"));
        su.setUsername("refreshuser");
        su.setEmail(EMAIL);
        su.setPasswordHash(passwordEncoder.encode(PASSWORD));
        su.setEmailVerified(true);
        su.setIsActive(true);
        su.setAccountLocked(false);
        systemUserRepository.save(su);

        // Application User 作成
        User appUser = new User();
        appUser.setUserId(USER_ID);
        appUser.setSystemUserId(su.getId());
        appUser.setTenantId("default");
        appUser.setUsername("refreshuser");
        appUser.setEmail(EMAIL);
        appUser.setDisplayName("Refresh Test User");
        appUser.setIsActive(true);
        appUser.setEmailVerified(true);
        appUser.setRoles("USER,ADMIN");
        appUser.setLastLoginAt(Instant.now());
        userRepository.save(appUser);
    }

    /**
     * ログインしてトークンを取得するヘルパー
     */
    private JsonNode loginAndGetTokens() throws Exception {
        String loginPayload = String.format(
                "{\"usernameOrEmail\":\"%s\",\"password\":\"%s\"}", EMAIL, PASSWORD);

        MvcResult result = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokens.accessToken").exists())
                .andExpect(jsonPath("$.tokens.refreshToken").exists())
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    @Test
    @DisplayName("Token Rotation: refresh で新 RT 発行 + 旧 RT が revoke される")
    void refreshShouldRotateToken() throws Exception {
        // 1. Login
        JsonNode loginResponse = loginAndGetTokens();
        String oldRefreshToken = loginResponse.path("tokens").path("refreshToken").asText();

        // 2. Refresh (body に refreshToken を載せる)
        String refreshPayload = String.format("{\"refreshToken\":\"%s\"}", oldRefreshToken);
        MvcResult refreshResult = mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(refreshPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokens.accessToken").exists())
                .andExpect(jsonPath("$.tokens.refreshToken").exists())
                .andReturn();

        JsonNode refreshResponse = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
        String newRefreshToken = refreshResponse.path("tokens").path("refreshToken").asText();

        // 3. 新旧が異なることを確認（rotation）
        assertThat(newRefreshToken).isNotEqualTo(oldRefreshToken);

        // 4. 新 RT で再度 refresh できることを確認
        String refresh2Payload = String.format("{\"refreshToken\":\"%s\"}", newRefreshToken);
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(refresh2Payload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokens.refreshToken").exists());
    }

    @Test
    @DisplayName("再利用検知: 旧 RT を再利用すると 401 + 全トークン revoke")
    void reuseDetectionShouldRevokeAllTokens() throws Exception {
        // 1. Login
        JsonNode loginResponse = loginAndGetTokens();
        String originalRefreshToken = loginResponse.path("tokens").path("refreshToken").asText();

        // 2. 正常 refresh → rotation が行われ旧 RT は revoke
        String refreshPayload = String.format("{\"refreshToken\":\"%s\"}", originalRefreshToken);
        MvcResult refreshResult = mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(refreshPayload))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode refreshResponse = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
        String newRefreshToken = refreshResponse.path("tokens").path("refreshToken").asText();

        // 3. 旧 RT を再利用 → 再利用検知で 401
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(refreshPayload))  // 旧 RT
                .andExpect(status().isUnauthorized());

        // 4. 新 RT も revoke されているはず → 401
        String newRefreshPayload = String.format("{\"refreshToken\":\"%s\"}", newRefreshToken);
        mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(newRefreshPayload))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Cookie フォールバック: body なしで Cookie の refreshToken から refresh 可能")
    void cookieFallbackRefresh() throws Exception {
        // 1. Login して Cookie を取得
        String loginPayload = String.format(
                "{\"usernameOrEmail\":\"%s\",\"password\":\"%s\"}", EMAIL, PASSWORD);

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andReturn();

        // レスポンスから refreshToken Cookie を抽出
        jakarta.servlet.http.Cookie refreshCookie = loginResult.getResponse().getCookie("refreshToken");
        assertThat(refreshCookie).isNotNull();
        assertThat(refreshCookie.getValue()).isNotEmpty();

        // 2. body なし（= F5後メモリ消失を模擬）+ Cookie のみで refresh
        MvcResult refreshResult = mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{}")  // body 空
                .cookie(new Cookie("refreshToken", refreshCookie.getValue())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tokens.accessToken").exists())
                .andExpect(jsonPath("$.tokens.refreshToken").exists())
                .andReturn();

        // 3. rotation により新しい refreshToken Cookie が返される
        jakarta.servlet.http.Cookie newRefreshCookie = refreshResult.getResponse().getCookie("refreshToken");
        assertThat(newRefreshCookie).isNotNull();
        assertThat(newRefreshCookie.getValue()).isNotEqualTo(refreshCookie.getValue());
    }

    @Test
    @DisplayName("Sliding Expiry: refresh のたびに新 RT の有効期限が延長される")
    void slidingExpiry() throws Exception {
        // 1. Login
        JsonNode loginResponse = loginAndGetTokens();
        String refreshToken = loginResponse.path("tokens").path("refreshToken").asText();

        Instant beforeRefresh = Instant.now();

        // 2. Refresh
        String refreshPayload = String.format("{\"refreshToken\":\"%s\"}", refreshToken);
        MvcResult refreshResult = mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(refreshPayload))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode refreshResponse = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
        String newRefreshToken = refreshResponse.path("tokens").path("refreshToken").asText();

        // 3. 新 RT の DB レコードを確認 → expiresAt が refresh 時点から 7 日後付近であること
        // (createRefreshToken が hashToken(tokenValue) で保存するため、ここでは hash を計算して検索)
        java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(newRefreshToken.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        RefreshToken newRt = refreshTokenRepository.findByTokenHash(hexString.toString())
                .orElseThrow(() -> new AssertionError("New refresh token not found in DB"));

        // expiresAt は now + 604800秒(7日) に近い値であること（前後 30 秒の誤差を許容）
        Instant expectedExpiry = beforeRefresh.plusSeconds(604800);
        assertThat(newRt.getExpiresAt()).isBetween(
                expectedExpiry.minusSeconds(30),
                expectedExpiry.plusSeconds(30));
    }

    @Test
    @DisplayName("JWT権限: refresh 後のアクセストークンにロール情報が含まれる")
    void refreshShouldPreserveRolesInJwt() throws Exception {
        // 1. Login
        JsonNode loginResponse = loginAndGetTokens();
        String refreshToken = loginResponse.path("tokens").path("refreshToken").asText();

        // 2. Refresh
        String refreshPayload = String.format("{\"refreshToken\":\"%s\"}", refreshToken);
        MvcResult refreshResult = mockMvc.perform(post("/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content(refreshPayload))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode refreshResponse = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
        String newAccessToken = refreshResponse.path("tokens").path("accessToken").asText();

        // 3. 新 access token で /auth/me にアクセス可能であること
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get("/auth/me")
                .header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.user.userId").value(USER_ID));

        // 4. JWT をデコードして roles claim を確認
        // JWT は header.payload.signature の形式
        String[] parts = newAccessToken.split("\\.");
        assertThat(parts).hasSize(3);

        String payloadJson = new String(java.util.Base64.getUrlDecoder().decode(parts[1]));
        JsonNode payload = objectMapper.readTree(payloadJson);

        assertThat(payload.has("roles")).isTrue();
        assertThat(payload.get("roles").isArray()).isTrue();
        assertThat(payload.get("roles").size()).isGreaterThanOrEqualTo(1);

        // roles に ROLE_USER と ROLE_ADMIN が含まれること
        boolean hasUser = false, hasAdmin = false;
        for (JsonNode role : payload.get("roles")) {
            if (role.asText().equals("ROLE_USER")) hasUser = true;
            if (role.asText().equals("ROLE_ADMIN")) hasAdmin = true;
        }
        assertThat(hasUser).as("JWT should contain ROLE_USER").isTrue();
        assertThat(hasAdmin).as("JWT should contain ROLE_ADMIN").isTrue();
    }

    @Test
    @DisplayName("refresh Cookie の maxAge が AuthProperties.refreshExpiration と一致")
    void refreshCookieMaxAgeShouldMatchConfig() throws Exception {
        // Login
        String loginPayload = String.format(
                "{\"usernameOrEmail\":\"%s\",\"password\":\"%s\"}", EMAIL, PASSWORD);

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(loginPayload))
                .andExpect(status().isOk())
                .andReturn();

        // refreshToken Cookie の maxAge を確認
        jakarta.servlet.http.Cookie refreshCookie = loginResult.getResponse().getCookie("refreshToken");
        assertThat(refreshCookie).isNotNull();
        // auth.jwt.refresh-expiration=604800 (7日)
        assertThat(refreshCookie.getMaxAge()).isEqualTo(604800);

        // accessToken Cookie の maxAge を確認
        jakarta.servlet.http.Cookie accessCookie = loginResult.getResponse().getCookie("accessToken");
        assertThat(accessCookie).isNotNull();
        // auth.jwt.expiration=3600 (1時間)
        assertThat(accessCookie.getMaxAge()).isEqualTo(3600);
    }
}
