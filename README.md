# mirelplatform

[![Build Status](https://dev.azure.com/vemicho/mir/_apis/build/status/vemic.promarker?branchName=master)](https://dev.azure.com/vemicho/mir/_build/latest?definitionId=2&branchName=azure-pipelines)

**mirelplatform** は、ビジネスアプリケーション開発のための包括的な統合プラットフォームです。  
SpringBootベースで構築されており、一般的なエンタープライズプラットフォームに加え、コード生成による開発効率化と、No-Code/Low-Code による柔軟なアプリケーション構築の両方を提供します。

## 🌟 主な機能

### 1. 基本機能

- **Mira AI(mirel Assistant):** 生成AIチャットボット
- JWT＆HttpOnly Cookies認証によるセキュアな認証管理
- RBAC(Role-Based Access Control)
- 柔軟なシステム管理、テナント管理、組織管理、ユーザ管理等

### 2. mirel Studio

**No-Code / Low-Code 統合開発環境 (IDE)**

モデル駆動でビジネスアプリケーションを視覚的に構築・運用するための統合環境です。  
データモデル、画面、ロジックをノーコードで定義し、即座に実行可能なアプリケーションとしてデプロイできます。

- **Modeler**: 業務データモデルの設計・定義
- **Form Designer**: ドラッグ＆ドロップによる画面レイアウト作成
- **Flow Designer**: ビジネスロジックのフロー定義
- **Data Browser**: データの閲覧・管理
- **Release Center**: アプリケーションのバージョン管理とリリース

### 3. ProMarker

**定型ソースコード生成プラットフォーム**

開発プロジェクトのテンプレートや機能スケルトンを自動生成するアプリケーションです。
定型的なディレクトリ構成やソースコード、初期データを独自技術で自動生成し、開発の高速化や品質の平準化に貢献します。

- **テンプレート管理**: FreeMarker を拡張した高度なテンプレートエンジン
- **アセット管理**: プロジェクト資産のセキュアな管理

---

## 🏗️ アーキテクチャ

**mirelplatform** は、堅牢で拡張性の高いモダンな技術スタックを採用しています。

### バックエンド (Backend)

- **Framework**: Spring Boot 3.3.0
- **Language**: Java 21 (Microsoft JVM)
- **Database**: PostgreSQL
- **Features**: JWT/OAuth2 認証, バッチ処理, テンプレートエンジン (Freemarker)

### フロントエンド (Frontend)

- **Framework**: React, Vite
- **Language**: TypeScript, Node.js 22.x
- **UI Component**: モダンなコンポーネント指向設計

### 開発・運用基盤

- **Container**: Docker, DevContainer Support
- **Testing**: Playwright (E2E), JUnit
- **Build**: Gradle (Backend), pnpm (Frontend)

---

## 🚀 セットアップガイド

### Docker環境

#### 前提条件

- Docker / Docker compose

#### 環境構築

1. Docker環境のpull
    ```bash
    docker pull ghcr.io/vemiorg/mirelplatform:latest
    ```
2. サービス起動
    ```bash
    docker-compose up -d
    ```

#### Docker-composeでの追加設定

準備中

### ローカル環境

#### 前提条件

- Java 21 (Microsoft JVM 推奨
- Node.js 22.x
- Gradle 8.4+
- Docker (オプション: DBや環境分離用)

#### 環境構築 (DevContainer / Codespaces)

1. **リポジトリのクローン**:

   ```bash
   git clone https://github.com/vemic/mirelplatform.git
   cd mirelplatform
   ```

2. **サービス起動**:
   便利なスクリプトを使用して、バックエンドとフロントエンドを一括で起動できます。

   ```bash
   # 全サービス起動 (Backend + Frontend)
   ./scripts/start-services.sh
   ```

3. **アプリケーションへのアクセス**:
   - **Frontend**: http://localhost:5173/
   - **Backend API**: http://localhost:3000/

### 開発用コマンド

`scripts` ディレクトリ内のユーティリティを活用することで、効率的な開発が可能です。

```bash
# サービスの起動
./scripts/start-services.sh

# サービスの停止
./scripts/stop-services.sh

# ログの監視 (Backend & Frontend)
./scripts/watch-logs.sh

# 起動状態の確認
./scripts/startup-monitor.sh
```

#### 個別起動の場合

**Backend (Spring Boot)**

```bash
SPRING_PROFILES_ACTIVE=dev SERVER_PORT=3000 ./gradlew :backend:bootRun
```

**Frontend (Vite)**

```bash
pnpm --filter frontend-v3 dev
# または
cd apps/frontend-v3 && npm run dev
```

---

## 📚 ドキュメント

詳細なドキュメントは `docs/` ディレクトリ配下に格納されています。

- **[mirel Studio ドキュメント](./docs/studio/00_INDEX.md)**: Studio の機能・仕様詳細
- **API 仕様**: [ProMarker 仕様書](./docs/promarker/01_SPECIFICATION.md)
- **E2E テスト**: [E2E Testing](./packages/e2e/README.md)

---

## 📄 ライセンス

Copyright (c) 2015-2025 vemi/mirelplatform. All rights reserved.

Licensed under the [LICENSE](./LICENSE) file.
