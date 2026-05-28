/*
 * Copyright(c) 2015-2025 mirelplatform.
 */
package jp.vemi.mirel.foundation.abst.dao.entity;

import jakarta.persistence.*;
import jakarta.persistence.Version;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;
import java.util.Date;

/**
 * リフレッシュトークンエンティティ.
 * トークンベースの認証でリフレッシュトークンを管理
 */
@Setter
@Getter
@Entity
@Table(name = "mir_refresh_token",
       indexes = {
           @Index(name = "idx_token_hash", columnList = "token_hash", unique = true),
           @Index(name = "idx_token_user", columnList = "user_id")
       })
public class RefreshToken {

    @Id
    @Column(name = "id", length = 36)
    private String id;

    @Column(name = "user_id", nullable = false, length = 36)
    private String userId;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "device_info")
    private String deviceInfo;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    /**
     * Token rotation: このトークンを置き換えた新トークンのハッシュ。
     * 再利用検知: revoked済みのトークンが再提示された場合、
     * このフィールドが non-null なら theft とみなしユーザーの全トークンを revoke する。
     */
    @Column(name = "replaced_by_token_hash")
    private String replacedByTokenHash;

    /** バージョン */
    @Version
    @Column(name = "version", nullable = false)
    private Long version = 1L;

    /** 削除フラグ */
    @Column(name = "delete_flag", columnDefinition = "boolean default false")
    private Boolean deleteFlag = false;

    /** 作成ユーザ */
    @Column(name = "create_user_id")
    private String createUserId;

    /** 作成日 */
    @Column(name = "create_date")
    private Date createDate;

    /** 更新ユーザ */
    @Column(name = "update_user_id")
    private String updateUserId;

    /** 更新日 */
    @Column(name = "update_date")
    private Date updateDate;

    @PrePersist
    public void onPrePersist() {
        if (this.id == null) {
            this.id = java.util.UUID.randomUUID().toString();
        }
        if (this.createdAt == null) {
            this.createdAt = Instant.now();
        }
        setDefault(this);
    }

    @PreUpdate
    public void onPreUpdate() {
        setDefault(this);
    }

    public static void setDefault(final RefreshToken entity) {
        if (entity.createDate == null) {
            entity.createDate = new Date();
        }
        if (entity.updateDate == null) {
            entity.updateDate = new Date();
        }
    }

    /**
     * トークンが有効かどうかを判定
     */
    public boolean isValid() {
        return this.revokedAt == null && 
               this.expiresAt.isAfter(Instant.now()) &&
               (this.deleteFlag == null || !this.deleteFlag);
    }
}
