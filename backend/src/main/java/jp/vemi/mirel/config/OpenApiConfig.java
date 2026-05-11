package jp.vemi.mirel.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI (Swagger) configuration for ProMarker Toolkit API.
 * 
 * <p>This configuration provides metadata for the API documentation including:
 * <ul>
 *   <li>API title, version, and description</li>
 *   <li>Contact information</li>
 *   <li>License information</li>
 *   <li>Server configurations for different environments</li>
 * </ul>
 * 
 * @see <a href="https://springdoc.org/">SpringDoc OpenAPI Documentation</a>
 * @see <a href="https://spec.openapis.org/oas/v3.0.3">OpenAPI Specification 3.0.3</a>
 */
@Configuration
public class OpenApiConfig {
    
    @Value("${server.servlet.context-path:/mipla2}")
    private String contextPath;
    
    @Value("${server.port:3000}")
    private String serverPort;
    
    /**
     * Configures OpenAPI metadata for the ProMarker Toolkit API.
     * 
     * @return OpenAPI configuration object
     */
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("ProMarker Toolkit API")
                .version("1.0.0")
                .description(buildDescription())
                .contact(new Contact()
                    .name("vemi/mirelplatform")
                    .email("contact@vemi.jp")
                    .url("https://github.com/vemiorg/mirelplatform"))
                .license(new License()
                    .name("Proprietary")
                    .url("https://github.com/vemiorg/mirelplatform/blob/master/LICENSE")))
            .servers(List.of(
                new Server()
                    .url("http://localhost:" + serverPort + contextPath)
                    .description("開発環境 (Development)"),
                new Server()
                    .url(contextPath)
                    .description("相対パス (Relative Path)")));
    }
    
    /**
     * Builds the API description with comprehensive platform information.
     * 
     * @return formatted API description
     */
    private String buildDescription() {
        return """
            ProMarker Toolkit は、テンプレートベースのコード生成と開発支援を提供する統合プラットフォームです。
            
            ## 主な機能
            
            ### 1. ステンシルマスタ管理
            - テンプレート（ステンシル）の読み込みと管理
            - カテゴリ別のテンプレート整理
            - バージョン管理とシリアル番号による追跡
            
            ### 2. コード生成
            - 選択したステンシルに基づくコード自動生成
            - パラメータ化されたテンプレート処理
            - 生成ファイルの自動ZIPアーカイブ化
            - ZIPファイルIDによるダウンロード管理
            
            ### 3. ファイル管理
            - セキュアなファイルアップロード
            - 一時ファイルの管理とクリーンアップ
            - バッチダウンロード（ZIP圧縮）
            
            ## 技術スタック
            - **Backend**: Spring Boot 3.3 (Java 21)
            - **Template Engine**: FreeMarker
            - **API Documentation**: SpringDoc OpenAPI 2.3.0
            - **Database**: H2 (開発), MySQL (本番)
            
            ## 認証
            本番環境ではJWT認証が必要です。開発環境では認証が無効化されています。
            
            ## 関連リソース
            - **Swagger UI**: `/swagger-ui.html`
            - **OpenAPI JSON**: `/api-docs`
            - **Frontend UI**: `/mirel/mste/` (ProMarker UI)
            - **H2 Console**: `/h2-console` (開発環境のみ)
            """;
    }
}
