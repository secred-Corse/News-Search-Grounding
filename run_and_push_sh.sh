#!/bin/bash
# ============================================================
# 脅威情報自動収集 + GitHubアップロード スクリプト
#
# Usage:
#   ./run_and_push.sh daily
#   ./run_and_push.sh weekly
#   ./run_and_push.sh custom 14
# ============================================================

# run_and_push_sh.sh の最初の方に追加
git config --global user.name "github-actions[bot]"
git config --global user.email "github-actions[bot]@users.noreply.github.com"

set -u  # 未定義変数の参照をエラーに（-eは外す：git commitが0件で失敗してもpushに進めるため）

# ----- 設定 -----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="${SCRIPT_DIR}/venv/bin/python"
LOG_DIR="${SCRIPT_DIR}/logs"
CRON_LOG="${LOG_DIR}/cron.log"

PERIOD="${1:-daily}"
DAYS="${2:-}"

# ----- ログヘルパー -----
mkdir -p "${LOG_DIR}"
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "${CRON_LOG}"
}

log "============================================================"
log "脅威情報収集 + GitHubアップロード開始 (period=${PERIOD})"
log "============================================================"

cd "${SCRIPT_DIR}" || { log "ERROR: cd失敗"; exit 1; }

# ----- 1. 脅威情報収集 -----
log "[1/3] 脅威情報収集を実行..."

if [ ! -x "${VENV_PYTHON}" ]; then
    log "ERROR: 仮想環境のPythonが見つかりません: ${VENV_PYTHON}"
    exit 1
fi

if [ "${PERIOD}" = "custom" ] && [ -n "${DAYS}" ]; then
    "${VENV_PYTHON}" threat_intel.py --period custom --days "${DAYS}"
else
    "${VENV_PYTHON}" threat_intel.py --period "${PERIOD}"
fi
COLLECT_RC=$?

if [ ${COLLECT_RC} -ne 0 ]; then
    log "ERROR: 脅威情報収集が失敗しました (exit=${COLLECT_RC})"
    exit ${COLLECT_RC}
fi
log "[1/3] 収集完了"

# ----- 2. Gitリポジトリ確認 -----
log "[2/3] Gitリポジトリの状態を確認..."

if [ ! -d ".git" ]; then
    log "ERROR: Gitリポジトリが初期化されていません"
    log "  → 'git init && git remote add origin <URL>' を先に実行してください"
    exit 1
fi

# リモート確認
if ! git remote get-url origin > /dev/null 2>&1; then
    log "ERROR: リモート 'origin' が設定されていません"
    exit 1
fi

# 現在のブランチ取得（HEADがdetachedの場合は'main'を使用）
BRANCH="$(git branch --show-current)"
BRANCH="${BRANCH:-main}"
log "  → ブランチ: ${BRANCH}"

# ----- 3. コミット & プッシュ -----
log "[3/3] reports/ と db/ の変更をコミット..."

# 対象パスをステージング（存在しなくてもエラーにしない）
git add reports/ 2>/dev/null || true
git add db/ 2>/dev/null || true

# 変更があるか確認
if git diff --cached --quiet; then
    log "  → 変更なし。コミット・プッシュをスキップします"
    log "完了"
    exit 0
fi

# コミット
COMMIT_MSG="Threat intel report: $(date '+%Y-%m-%d %H:%M') (${PERIOD})"
if git commit -m "${COMMIT_MSG}"; then
    log "  → コミット成功: ${COMMIT_MSG}"
else
    log "ERROR: コミット失敗"
    exit 1
fi

# プッシュ（リトライ付き）
PUSH_RETRIES=3
for i in $(seq 1 ${PUSH_RETRIES}); do
    if git push origin "${BRANCH}"; then
        log "  → プッシュ成功（${i}回目）"
        break
    else
        if [ ${i} -lt ${PUSH_RETRIES} ]; then
            log "  → プッシュ失敗（${i}/${PUSH_RETRIES}）。10秒後にリトライ..."
            sleep 10
        else
            log "ERROR: プッシュ失敗（${PUSH_RETRIES}回試行）"
            exit 1
        fi
    fi
done

log "============================================================"
log "完了"
log "============================================================"
