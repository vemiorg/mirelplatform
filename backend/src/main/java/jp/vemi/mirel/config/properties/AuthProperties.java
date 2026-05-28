package jp.vemi.mirel.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import lombok.Getter;
import lombok.Setter;

@Configuration
@ConfigurationProperties(prefix = "auth")
@Getter
@Setter
public class AuthProperties {

    /**
     * 認証方式 (jwt または session)
     */
    private String method = "jwt";

    /**
     * JWT設定
     */
    private Jwt jwt = new Jwt();

    @Getter
    @Setter
    public static class Jwt {
        /**
         * JWT認証の有効/無効
         */
        private boolean enabled = true;

        /**
         * HMAC署名用シークレットキー (32文字以上推奨)
         */
        private String secret;

        /**
         * アクセストークン有効期限 (秒)
         */
        private long expiration = 3600;

        /**
         * リフレッシュトークン有効期限 (秒)
         * デフォルト: 7日 (604800秒)。Cookie maxAge と一致させること。
         */
        private long refreshExpiration = 604800;

        /**
         * rememberMe 有効時のリフレッシュトークン有効期限 (秒)
         * デフォルト: 90日
         */
        private long rememberMeRefreshExpiration = 7776000;
    }
}
