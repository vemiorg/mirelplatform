/*
 * Copyright(c) 2015-2025 mirelplatform.
 */
package jp.vemi.mirel.apps.mira.infrastructure.ai;

import java.time.Duration;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.client.ChatClient.ChatClientRequestSpec;
import org.springframework.ai.chat.messages.AssistantMessage;
import org.springframework.ai.chat.messages.AssistantMessage.ToolCall;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.SystemMessage;
import org.springframework.ai.chat.messages.ToolResponseMessage;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.ai.openai.OpenAiChatModel;
import org.springframework.ai.openai.OpenAiChatOptions;
import org.springframework.ai.openai.api.OpenAiApi;
import org.springframework.http.HttpHeaders;
import org.springframework.ai.retry.RetryUtils;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.reactive.function.client.WebClient;

import jp.vemi.mirel.apps.mira.infrastructure.config.MiraAiProperties;
import lombok.extern.slf4j.Slf4j;
import reactor.netty.http.client.HttpClient;

/**
 * GitHub Models API クライアント.
 * 
 * <p>
 * Spring AI ChatClient を使用して実装（OpenAiApiを手動構築）。
 * </p>
 */
@Slf4j
@Component
public class GitHubModelsClient implements AiProviderClient {

    private static final String PROVIDER_NAME = "github-models";
    private final MiraAiProperties properties;
    private final ChatClient chatClient;
    private final boolean available;

    public GitHubModelsClient(MiraAiProperties properties) {
        this.properties = properties;
        var config = properties.getGithubModels();

        if (config.getApiKey() == null || config.getApiKey().isBlank()) {
            log.warn("GitHub Models API key is not configured. Client will be disabled.");
            this.chatClient = null;
            this.available = false;
        } else {
            this.chatClient = buildChatClient(config);
            this.available = true;
        }
    }

    private ChatClient buildChatClient(MiraAiProperties.GitHubModelsConfig config) {
        log.info("Initializing GitHubModelsClient with model: {}", config.getModel());

        // 1. Create OpenAiApi
        org.springframework.ai.model.ApiKey apiKey = new org.springframework.ai.model.SimpleApiKey(config.getApiKey());

        // Use custom interceptor and message converters
        RestClient.Builder safeRestClientBuilder = RestClient.builder()
                .requestInterceptor(new GitHubModelsInterceptor())
                .messageConverters(c -> c
                        .add(new org.springframework.http.converter.json.MappingJackson2HttpMessageConverter()));

        // Use custom WebClient builder with filter and timeout
        // タイムアウトを設定値から取得（gpt-5-mini / o1 モデルの思考時間対策。環境ごとに調整可能）
        int timeoutSeconds = config.getTimeoutSeconds() != null ? config.getTimeoutSeconds() : 300; // デフォルト5分
        HttpClient httpClient = HttpClient.create()
                .responseTimeout(Duration.ofSeconds(timeoutSeconds));

        WebClient.Builder webClientBuilder = WebClient.builder()
                .clientConnector(new org.springframework.http.client.reactive.ReactorClientHttpConnector(httpClient))
                .filter(new GitHubModelsWebClientFilter());

        OpenAiApi openAiApi = new OpenAiApi(
                config.getBaseUrl(),
                apiKey,
                new HttpHeaders(),
                "/chat/completions",
                "/embeddings",
                safeRestClientBuilder,
                webClientBuilder,
                RetryUtils.DEFAULT_RESPONSE_ERROR_HANDLER);

        // 2. Create ChatModel
        OpenAiChatOptions options = OpenAiChatOptions.builder()
                .model(config.getModel())
                .temperature(config.getTemperature())
                .maxTokens(config.getMaxTokens())
                .build();

        OpenAiChatModel chatModel = OpenAiChatModel.builder()
                .openAiApi(openAiApi)
                .defaultOptions(options)
                .build();

        // 3. Create ChatClient
        return ChatClient.builder(chatModel)
                .build();
    }

    @Override
    public AiResponse chat(AiRequest request) {
        if (!available || chatClient == null) {
            return AiResponse.error("PROVIDER_NOT_AVAILABLE", "GitHub Models is not configured.");
        }

        var config = properties.getGithubModels();
        long startTime = System.currentTimeMillis();

        try {
            // 5. Build Prompt
            List<Message> messages = request.getMessages().stream()
                    .map(this::mapMessage)
                    .collect(Collectors.toList());

            Prompt prompt = new Prompt(messages);
            ChatClientRequestSpec requestSpec = chatClient.prompt(prompt);

            // Add tools to request spec (so they appear in API request)
            if (request.getToolCallbacks() != null) {
                for (org.springframework.ai.tool.ToolCallback tc : request.getToolCallbacks()) {
                    requestSpec.tools(tc);
                }
            }

            // GPT-5/o1 models logic (maxCompletionTokens) is handled in properties/options
            // mostly,
            // but if per-request override is needed, we might need to recreate options.
            // For now assuming default options are sufficient or standard params work.
            // NOTE: Dynamic max_tokens vs max_completion_tokens switch is tricky with
            // pre-built client
            // unless we pass OpenAiChatOptions to call().

            // Check if we need to set maxCompletionTokens dynamically
            boolean isGpt5Model = config.getModel() != null &&
                    (config.getModel().contains("gpt-5") || config.getModel().contains("o1")
                            || config.getModel().contains("o3"));

            Integer tokenLimit = request.getMaxTokens() != null ? request.getMaxTokens() : config.getMaxTokens();

            OpenAiChatOptions.Builder optionsBuilder = OpenAiChatOptions.builder();
            if (isGpt5Model) {
                optionsBuilder.maxCompletionTokens(tokenLimit);
            } else {
                optionsBuilder.maxTokens(tokenLimit);
            }
            if (request.getTemperature() != null) {
                optionsBuilder.temperature(request.getTemperature());
            }
            requestSpec.options(optionsBuilder.build());

            // Execute
            ChatResponse response = requestSpec
                    .call()
                    .chatResponse();

            long latency = System.currentTimeMillis() - startTime;

            // 7. Map to AiResponse
            if (response.getResult() == null) {
                return AiResponse.error("EMPTY_RESPONSE", "No result");
            }

            String content = response.getResult().getOutput().getText();
            AssistantMessage outputMsg = response.getResult().getOutput();

            List<AiRequest.Message.ToolCall> toolCalls = null;
            if (outputMsg.getToolCalls() != null && !outputMsg.getToolCalls().isEmpty()) {
                toolCalls = outputMsg.getToolCalls().stream()
                        .map(tc -> new AiRequest.Message.ToolCall(tc.id(), tc.type(), tc.name(), tc.arguments()))
                        .collect(Collectors.toList());
            }

            AiResponse.Metadata metadata = AiResponse.Metadata.builder()
                    .model(config.getModel())
                    .latencyMs(latency)
                    .build();

            AiResponse aiResponse = AiResponse.success(content, metadata);
            aiResponse.setToolCalls(toolCalls);
            return aiResponse;

        } catch (org.springframework.web.client.RestClientResponseException e) {
            String responseBody = e.getResponseBodyAsString();
            log.error("[GitHubModels] API Request failed: Status={} Body={}", e.getStatusCode(), responseBody, e);
            return AiResponse.error("API_ERROR", "AIプロバイダーエラー (" + e.getStatusCode() + "): " + responseBody);
        } catch (Exception e) {
            log.error("[GitHubModels] Request failed: {} (Cause: {})", e.getMessage(), e.getClass().getName(), e);
            return AiResponse.error("REQUEST_FAILED",
                    "システムエラーが発生しました: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    @Override
    public reactor.core.publisher.Flux<AiResponse> stream(AiRequest request) {
        if (!available || chatClient == null) {
            return reactor.core.publisher.Flux
                    .just(AiResponse.error("PROVIDER_NOT_AVAILABLE", "GitHub Models is not configured."));
        }
        var config = properties.getGithubModels();

        try {
            // 5. Build Prompt
            List<Message> messages = request.getMessages().stream()
                    .map(this::mapMessage)
                    .collect(Collectors.toList());

            Prompt prompt = new Prompt(messages);
            ChatClientRequestSpec requestSpec = chatClient.prompt(prompt);

            // Add tools to request spec
            if (request.getToolCallbacks() != null) {
                for (org.springframework.ai.tool.ToolCallback tc : request.getToolCallbacks()) {
                    requestSpec.tools(tc);
                }
            }

            // Dynamic Options
            boolean isGpt5Model = config.getModel() != null &&
                    (config.getModel().contains("gpt-5") || config.getModel().contains("o1")
                            || config.getModel().contains("o3"));

            Integer tokenLimit = request.getMaxTokens() != null ? request.getMaxTokens() : config.getMaxTokens();

            OpenAiChatOptions.Builder optionsBuilder = OpenAiChatOptions.builder();
            if (isGpt5Model) {
                optionsBuilder.maxCompletionTokens(tokenLimit);
            } else {
                optionsBuilder.maxTokens(tokenLimit);
            }
            if (request.getTemperature() != null) {
                optionsBuilder.temperature(request.getTemperature());
            }
            requestSpec.options(optionsBuilder.build());

            // Execute Stream
            return requestSpec.stream()
                    .chatResponse()
                    .timeout(Duration.ofMinutes(5)) // Fluxレベルでもタイムアウト
                    .map(this::mapStreamResponse)
                    .onErrorResume(e -> {
                        if (e instanceof org.springframework.web.reactive.function.client.WebClientResponseException) {
                            org.springframework.web.reactive.function.client.WebClientResponseException webEx = (org.springframework.web.reactive.function.client.WebClientResponseException) e;
                            String errorBody = webEx.getResponseBodyAsString();
                            log.error("[GitHubModels] Stream API Error: {} Body: {}", webEx.getStatusCode(), errorBody);

                            String userMessage = "申し訳ございません。AIサービスで一時的なエラーが発生しました。しばらく待ってから再度お試しください。";

                            if (errorBody.contains("extra_body")) {
                                userMessage = "AIモデルの設定に問題があります。システム管理者に連絡してください。";
                                log.error("[GitHubModels] extra_body parameter not supported.");
                            } else if (errorBody.contains("max_completion_tokens")
                                    || errorBody.contains("max_tokens")) {
                                userMessage = "AIモデルのトークン設定に問題があります。システム管理者に連絡してください。";
                            }

                            return reactor.core.publisher.Flux.just(
                                    AiResponse.builder()
                                            .content(userMessage)
                                            .metadata(AiResponse.Metadata.builder().model(config.getModel()).build())
                                            .build());
                        }
                        log.error("[GitHubModels] Stream Request failed", e);
                        return reactor.core.publisher.Flux.just(
                                AiResponse.builder()
                                        .content("申し訳ございません。予期しないエラーが発生しました。")
                                        .metadata(AiResponse.Metadata.builder().model(config.getModel()).build())
                                        .build());
                    });

        } catch (Exception e) {
            log.error("[GitHubModels] Request setup failed", e);
            return reactor.core.publisher.Flux.just(
                    AiResponse.error("SETUP_FAILED", "リクエスト設定中にエラーが発生しました: " + e.getMessage()));
        }
    }

    private AiResponse mapStreamResponse(ChatResponse response) {
        String content = "";
        if (response.getResult() != null && response.getResult().getOutput().getText() != null) {
            content = response.getResult().getOutput().getText();
        }

        List<AiRequest.Message.ToolCall> toolCalls = null;
        if (response.getResult() != null && response.getResult().getOutput().getToolCalls() != null
                && !response.getResult().getOutput().getToolCalls().isEmpty()) {
            toolCalls = response.getResult().getOutput().getToolCalls().stream()
                    .map(tc -> new AiRequest.Message.ToolCall(tc.id(), tc.type(), tc.name(), tc.arguments()))
                    .collect(Collectors.toList());
        }

        AiResponse.Metadata metadata = AiResponse.Metadata.builder()
                .model(properties.getGithubModels().getModel())
                .build();

        AiResponse aiResponse = AiResponse.builder()
                .content(content)
                .metadata(metadata)
                .build();
        aiResponse.setToolCalls(toolCalls);
        return aiResponse;
    }

    private Message mapMessage(AiRequest.Message msg) {
        switch (msg.getRole()) {
            case "user":
                return new UserMessage(msg.getContent());
            case "system":
                return new SystemMessage(msg.getContent());
            case "assistant":
                if (msg.getToolCalls() != null && !msg.getToolCalls().isEmpty()) {
                    List<ToolCall> springToolCalls = msg.getToolCalls().stream()
                            .map(tc -> new ToolCall(tc.getId(), tc.getType(), tc.getName(), tc.getArguments()))
                            .collect(Collectors.toList());
                    return AssistantMessage.builder()
                            .content(msg.getContent())
                            .toolCalls(springToolCalls)
                            .build();
                }
                return AssistantMessage.builder().content(msg.getContent()).build();
            case "tool":
                return ToolResponseMessage.builder()
                        .responses(List.of(
                                new ToolResponseMessage.ToolResponse(
                                        msg.getToolCallId() != null ? msg.getToolCallId() : "unknown_id",
                                        msg.getToolName() != null ? msg.getToolName() : "unknown_name",
                                        msg.getContent())))
                        .build();
            default:
                return new UserMessage(msg.getContent());
        }
    }

    @Override
    public boolean isAvailable() {
        return available;
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    @Slf4j
    static class GitHubModelsInterceptor implements org.springframework.http.client.ClientHttpRequestInterceptor {

        private final com.fasterxml.jackson.databind.ObjectMapper objectMapper = new com.fasterxml.jackson.databind.ObjectMapper();

        @Override
        public org.springframework.http.client.ClientHttpResponse intercept(
                org.springframework.http.HttpRequest request, byte[] body,
                org.springframework.http.client.ClientHttpRequestExecution execution) throws java.io.IOException {

            if (body.length == 0) {
                return execution.execute(request, body);
            }

            try {
                com.fasterxml.jackson.databind.JsonNode root = objectMapper.readTree(body);
                com.fasterxml.jackson.databind.node.ObjectNode rootObj = (com.fasterxml.jackson.databind.node.ObjectNode) root;
                boolean modified = false;

                if (rootObj.has("extra_body")) {
                    log.debug("[GitHubModelsInterceptor] Removing 'extra_body' parameter");
                    rootObj.remove("extra_body");
                    modified = true;
                }

                if (root.has("messages") && root.get("messages").isArray()) {
                    com.fasterxml.jackson.databind.node.ArrayNode messages = (com.fasterxml.jackson.databind.node.ArrayNode) root
                            .get("messages");
                    for (com.fasterxml.jackson.databind.JsonNode msg : messages) {
                        if (msg.has("role") && "assistant".equals(msg.get("role").asText())) {
                            if (msg.has("tool_calls") && !msg.get("tool_calls").isEmpty()) {
                                if (!msg.has("content")) {
                                    ((com.fasterxml.jackson.databind.node.ObjectNode) msg).putNull("content");
                                    modified = true;
                                }
                            }
                        }
                    }
                }

                if (modified) {
                    byte[] newBody = objectMapper.writeValueAsBytes(root);
                    request.getHeaders().setContentLength(newBody.length);
                    return execution.execute(request, newBody);
                }

            } catch (Exception e) {
                log.warn("Failed to intercept and fix GitHub Models request body", e);
            }

            return execution.execute(request, body);
        }
    }

    @Slf4j
    static class GitHubModelsWebClientFilter
            implements org.springframework.web.reactive.function.client.ExchangeFilterFunction {

        @Override
        public reactor.core.publisher.Mono<org.springframework.web.reactive.function.client.ClientResponse> filter(
                org.springframework.web.reactive.function.client.ClientRequest request,
                org.springframework.web.reactive.function.client.ExchangeFunction next) {

            if (!"POST".equals(request.method().name())) {
                return next.exchange(request);
            }
            return next.exchange(request)
                    .onErrorResume(org.springframework.web.reactive.function.client.WebClientResponseException.class,
                            error -> {
                                String errorBody = error.getResponseBodyAsString();
                                log.error("[GitHubModelsWebClientFilter] API Error: {} {}", error.getStatusCode(),
                                        errorBody);
                                return reactor.core.publisher.Mono.error(error);
                            });
        }
    }
}
