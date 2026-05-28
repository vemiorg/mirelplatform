/*
 * Copyright(c) 2015-2024 mirelplatform.
 */
package jp.vemi.mirel.foundation.abst.dao.repository;

import jp.vemi.mirel.foundation.abst.dao.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * RefreshTokenリポジトリ.
 */
@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    /**
     * トークンハッシュで検索
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.tokenHash = :tokenHash AND rt.deleteFlag = false")
    Optional<RefreshToken> findByTokenHash(@Param("tokenHash") String tokenHash);

    /**
     * ユーザIDに紐づく有効なトークンを取得
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND " +
           "rt.revokedAt IS NULL AND rt.expiresAt > :now AND rt.deleteFlag = false")
    List<RefreshToken> findValidTokensByUserId(@Param("userId") String userId, @Param("now") Instant now);

    /**
     * 期限切れトークンを削除
     */
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now OR rt.revokedAt IS NOT NULL")
    void deleteExpiredTokens(@Param("now") Instant now);

    /**
     * ユーザーの全有効トークンを取得（再利用検知時の一括 revoke 用）
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.userId = :userId AND " +
           "rt.revokedAt IS NULL AND rt.deleteFlag = false")
    List<RefreshToken> findAllActiveByUserId(@Param("userId") String userId);
}
