#!/bin/bash
# ============================================================
# 脅威情報自動収集 + GitHubアップロード スクリプト
#
# Usage:
#   ./run_and_push.sh daily
#   ./run_and_push.sh weekly
#   ./run_and_push.sh custom 14
# ============================================================

# 1. Gitのユーザー設定（Actionsのbotとして振る舞う）
git config --global user.name "github-actions[bot]"
git config --global user.email "github-actions[bot]@users.noreply.github.com"

set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# GitHub Actionsでは venv ではなくシステムの python3 を使うことが多いので柔軟に変更
PYTHON_BIN=$(command -v python3)
LOG_DIR="${SCRIPT_DIR}/logs"
CRON_LOG="${LOG_DIR}/cron.log"

PERIOD="${1:-daily}"
DAYS="${2:-}"

mkdir -p "${LOG_DIR}"
cd "${SCRIPT_DIR}"

echo "[$(date)] 収集開始..."

# 2. Python実行（ファイル名を threat_intel_python.py に修正）
if [ "${PERIOD}" = "custom" ] && [ -n "${DAYS}" ]; then
    $PYTHON_BIN threat_intel_python.py --period custom --days "${DAYS}"
else
    $PYTHON_BIN threat_intel_python.py --period "${PERIOD}"
fi

# 3. 変更をリポジトリに戻す処理
echo "[$(date)] リポジトリへの反映チェック..."

# dbとreportsディレクトリを明示的に追加
git add reports/*.md
git add db/threats.sqlite 2>/dev/null || true

# 変更がある場合のみコミット
if ! git diff --cached --quiet; then
    COMMIT_MSG="Threat intel report: $(date '+%Y-%m-%d %H:%M') (${PERIOD})"
    git commit -m "${COMMIT_MSG}"
    
    # プッシュ（Actionsからだと単純な git push で通ります）
    git push origin HEAD
    echo "Successfully pushed changes to repository."
else
    echo "No changes detected. Skipping push."
fi
