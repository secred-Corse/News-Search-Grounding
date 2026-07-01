#!/usr/bin/env python3
"""
脅威情報自動収集ツール (Threat Intelligence Collector)

Anthropic API + Web Search を使ってマルウェア・APT・脆弱性情報を収集し、
SQLiteで重複排除しつつMarkdownレポートを生成する。

Usage:
    python threat_intel.py --period daily
    python threat_intel.py --period weekly
    python threat_intel.py --period custom --days 14
"""

import argparse
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import yaml
from dotenv import load_dotenv
from google import genai
from google.genai import types

import time
from google import genai
from google.genai import types, errors  # errors を追加


# ============================================================
# 初期化
# ============================================================
load_dotenv() # .envがあれば読み込む

# Kali環境変数または.envから取得
# GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
GOOGLE_API_KEY = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_CONFIG_PATH = SCRIPT_DIR / "config.yaml"


# ============================================================
# ログ設定
# ============================================================
def setup_logger(log_dir: Path) -> logging.Logger:
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "threat_intel.log"

    logger = logging.getLogger("threat_intel")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    return logger


# ============================================================
# 設定読込
# ============================================================
def load_config(path: Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"設定ファイルが見つかりません: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ============================================================
# SQLite管理
# ============================================================
class ThreatDB:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        # 既存の threats テーブル (変更なし)
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hash TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            threat_level TEXT,
            summary TEXT,
            tags TEXT,
            source TEXT,
            publish_date TEXT,
            collected_at TEXT NOT NULL,
            keyword TEXT
        );
        """)
        # 追加：実行履歴管理テーブル
        self.conn.execute("""
        CREATE TABLE IF NOT EXISTS run_history (
            keyword TEXT,
            target_date TEXT,
            status TEXT, -- 'SUCCESS' or 'ERROR'
            error_message TEXT,
            updated_at TEXT,
            PRIMARY KEY (keyword, target_date)
        );
        """)
        self.conn.commit()

    @staticmethod
    def make_hash(title: str, source: str) -> str:
        """タイトル＋ソースから重複検出用ハッシュを生成"""
        normalized = (title.strip().lower() + "|" + (source or "").strip().lower())
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def insert_if_new(self, item: dict, keyword: str) -> bool:
        """新規ならINSERTしてTrueを返す。既存はFalse。"""
        h = self.make_hash(item.get("title", ""), item.get("source", ""))
        try:
            self.conn.execute("""
                INSERT INTO threats
                (hash, title, threat_level, summary, tags, source, publish_date, collected_at, keyword)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                h,
                item.get("title", ""),
                item.get("threatLevel", "INFO"),
                item.get("summary", ""),
                json.dumps(item.get("tags", []), ensure_ascii=False),
                item.get("source", ""),
                item.get("date", ""),
                datetime.now().isoformat(timespec="seconds"),
                keyword,
            ))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def get_recent(self, since_iso: str) -> list:
        """指定日時以降に収集したレコードを取得"""
        cur = self.conn.execute("""
            SELECT * FROM threats
            WHERE collected_at >= ?
            ORDER BY
                CASE threat_level
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3
                    WHEN 'LOW' THEN 4
                    ELSE 5
                END,
                publish_date DESC
        """, (since_iso,))
        return [dict(r) for r in cur.fetchall()]

    def is_already_done(self, keyword, target_date):
        """本日、そのキーワードが既に成功しているか確認"""
        cur = self.conn.execute(
            "SELECT status FROM run_history WHERE keyword = ? AND target_date = ? AND status = 'SUCCESS'",
            (keyword, target_date)
        )
        return cur.fetchone() is not None

    def update_history(self, keyword, target_date, status, error_msg=""):
        """実行結果を記録"""
        self.conn.execute("""
            INSERT OR REPLACE INTO run_history (keyword, target_date, status, error_message, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (keyword, target_date, status, error_msg, datetime.now().isoformat()))
        self.conn.commit()

    def close(self):
        self.conn.close()


# ============================================================
# Claude APIクライアント
# ============================================================
class ThreatCollector:
    def __init__(self, model_name: str, max_tokens: int, logger: logging.Logger):
        if not GOOGLE_API_KEY:
            logger.error("GOOGLE_API_KEY が環境変数に設定されていません。")
            raise RuntimeError("API Key Missing")
        
        self.client = genai.Client(api_key=GOOGLE_API_KEY)
        self.model_id = model_name
        self.max_tokens = max_tokens
        self.logger = logger

    def collect(self, keyword: str, from_date: str, to_date: str, max_items: int) -> list:
        all_items = []
        batch_size = 10
        rounds = max(1, (max_items + batch_size - 1) // batch_size)

        for r in range(rounds):
            # --- 15 RPM 制限対策: 各リクエストの前に 5秒待機 ---
            if r > 0 or len(all_items) > 0:
                self.logger.info("  └─ レート制限回避のため 5秒待機中...")
                time.sleep(5)

            remaining = max_items - len(all_items)
            if remaining <= 0:
                break
            n = min(batch_size, remaining)

            seen_titles = [it.get("title", "") for it in all_items]
            exclude_block = ""
            if seen_titles:
                exclude_block = (
                    "\nDO NOT include items whose title matches any of the following:\n- "
                    + "\n- ".join(seen_titles[-20:]) + "\n"
                )

            prompt = self._build_prompt(keyword, from_date, to_date, n, exclude_block)
            self.logger.info(f"  └─ Round {r + 1}/{rounds}: {n}件を要求")

            try:
                # _call_api 内部でのリトライ時もスリープが入るようになっています
                items = self._call_api(prompt)
            except Exception as e:
                self.logger.warning(f"  └─ API呼び出し失敗: {e}")
                raise e 

            if not items:
                break

            items = self._filter_by_date(items, from_date, to_date)
            all_items.extend(items)

        return all_items

    def _build_prompt(self, keyword: str, from_date: str, to_date: str, n: int, exclude_block: str) -> str:
        return (
            f"You are a cybersecurity threat intelligence analyst. Today is {to_date}. "
            f"Search the web for threat information about \"{keyword}\" "
            "(malware, APT groups, vulnerabilities, cyberattacks).\n\n"
            f"STRICT DATE FILTER: Only include items published between {from_date} and {to_date} (inclusive). "
            f"Exclude anything published before {from_date}. If the publication date cannot be confirmed within "
            "this range, exclude the item.\n"
            f"{exclude_block}\n"
            f"Return ONLY a JSON array with up to {n} items. No markdown, no explanation, no code fences.\n\n"
            "Rules:\n"
            "- Double quotes for all keys and strings\n"
            "- No single quotes, backticks, or unescaped special characters inside string values\n"
            "- Keep summary concise (2-4 sentences)\n"
            "- All text fields in Japanese\n"
            "- \"date\" must be in YYYY-MM-DD format\n"
            "- tags: type must be one of \"apt\", \"malware\", \"other\". Use \"other\" for CVE numbers, "
            "products, attack techniques, target sectors, etc.\n\n"
            "Schema:\n"
            "[{\"title\":\"...\",\"threatLevel\":\"CRITICAL|HIGH|MEDIUM|LOW|INFO\","
            "\"summary\":\"...\",\"tags\":[{\"type\":\"apt|malware|other\",\"label\":\"...\"}],"
            "\"source\":\"...\",\"date\":\"YYYY-MM-DD\"}]"
        )

    def _call_api(self, prompt: str) -> list:
        max_retries = 3
        retry_delay = 10  # 500エラー時は少し長めに待機

        for attempt in range(max_retries):
            try:
                search_tool = types.Tool(google_search=types.GoogleSearch())

                response = self.client.models.generate_content(
                    model=self.model_id,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        max_output_tokens=self.max_tokens,
                        temperature=0.1,
                        tools=[search_tool]
                    )
                )

                if not response or not response.text:
                    return []

                return self._parse_json(response.text)

            except errors.ClientError as e:
                # クライアント側のエラー（認証エラー、引数ミスなど）はリトライしない
                self.logger.error(f"  └─ クライアントエラー: {e}")
                raise e # ← 【修正】例外を投げる
            
            except (errors.ServerError, Exception) as e:
                # 500/503エラー、およびその他の通信エラーをここでキャッチ
                if attempt < max_retries - 1:
                    wait_time = retry_delay * (attempt + 1) # 直線的に待ち時間を増やす
                    self.logger.warning(f"  └─ サーバー一時エラー({e})。{wait_time}秒後に再試行 ({attempt+1}/{max_retries})")
                    time.sleep(wait_time)
                else:
                    raise RuntimeError(f"API最大リトライ到達: {e}")
                    self.logger.error("  └─ 最大再試行回数に達したため、このキーワードをスキップします。")
                    return []

    def _parse_json(self, text: str) -> list:
        # JSON抽出処理を分離して堅牢化
        cleaned = re.sub(r"```json|```", "", text).strip()
        # ... (既存の抽出ロジック)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            # 軽微な末尾欠けを修復
            if not json_str.endswith("]"):
                json_str += "]"
            try:
                return json.loads(json_str)
            except:
                return []

    @staticmethod
    def _filter_by_date(items: list, from_date: str, to_date: str) -> list:
        from_d = datetime.strptime(from_date, "%Y-%m-%d")
        to_d = datetime.strptime(to_date, "%Y-%m-%d") + timedelta(days=1) - timedelta(seconds=1)
        result = []
        for item in items:
            d_str = item.get("date", "")
            if not d_str:
                continue
            try:
                if re.match(r"^\d{4}-\d{2}$", d_str):
                    d = datetime.strptime(d_str + "-01", "%Y-%m-%d")
                else:
                    d = datetime.strptime(d_str, "%Y-%m-%d")
            except ValueError:
                continue
            if from_d <= d <= to_d:
                result.append(item)
        return result


# ============================================================
# Markdown生成
# ============================================================
LEVEL_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
LEVEL_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "⚪",
}


def render_markdown(records: list, period_label: str, from_date: str, to_date: str,
                    new_count: int, error_count: int, error_keywords: list) -> str:
    lines = []
    today = datetime.now().strftime("%Y-%m-%d")

    lines.append(f"# 脅威情報レポート {today}")
    lines.append("")
    lines.append(f"**収集期間：** {from_date} 〜 {to_date}（{period_label}）")
    lines.append(f"**新規検出：** {new_count}件")

    # --- 追加: エラーがあった場合の警告文をレポートに埋め込む ---
    if error_count > 0:
        lines.append("")
        lines.append(f"⚠️ **【警告】APIエラー発生**")
        lines.append(f"{error_count}件のキーワードがAPIエラー（500エラー等）により収集できず、スキップされました。")
        lines.append(f"（対象キーワード: `{', '.join(error_keywords)}`）")

    lines.append("")
    lines.append("---")
    lines.append("")

    if not records:
        lines.append("⚠️ 新規の脅威情報は検出されませんでした。")
        return "\n".join(lines)

    # 脅威レベル別にグルーピング
    grouped = {lv: [] for lv in LEVEL_ORDER}
    for r in records:
        lv = r.get("threat_level") or "INFO"
        if lv not in grouped:
            lv = "INFO"
        grouped[lv].append(r)

    for level in LEVEL_ORDER:
        items = grouped[level]
        if not items:
            continue
        lines.append(f"## {LEVEL_ICON[level]} {level} ({len(items)}件)")
        lines.append("")
        for i, r in enumerate(items, 1):
            lines.extend(_render_card(i, r))
            lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _render_card(idx: int, r: dict) -> list:
    """1件の脅威情報をMarkdownカード形式で出力"""
    lines = []
    lines.append(f"### {idx}. {r.get('title', '(タイトル不明)')}")
    lines.append("")

    # タグ
    try:
        tags = json.loads(r.get("tags") or "[]")
    except json.JSONDecodeError:
        tags = []
    if tags:
        tag_strs = []
        for t in tags:
            label = t.get("label", "")
            ttype = t.get("type", "other")
            prefix = {"apt": "🎯", "malware": "🦠", "other": "🏷"}.get(ttype, "🏷")
            tag_strs.append(f"{prefix} `{label}`")
        lines.append(f"**🏷 タグ：** {' / '.join(tag_strs)}  ")

    if r.get("publish_date"):
        lines.append(f"**📅 公開日：** {r['publish_date']}  ")
    if r.get("source"):
        lines.append(f"**🔗 出典：** {r['source']}  ")
    if r.get("keyword"):
        lines.append(f"**🔑 検出キーワード：** `{r['keyword']}`")
    lines.append("")
    if r.get("summary"):
        lines.append(f"> {r['summary']}")

    return lines


# ============================================================
# 期間計算
# ============================================================
def calc_period(period: str, custom_days: int = None) -> tuple:
    """(period_label, from_date, to_date, days) を返す"""
    today = datetime.now()
    if period == "daily":
        days = 1
        label = "日次（過去1日）"
    elif period == "weekly":
        days = 7
        label = "週次（過去7日）"
    elif period == "custom":
        days = custom_days or 7
        label = f"カスタム（過去{days}日）"
    else:
        raise ValueError(f"不正な期間指定: {period}")

    from_date = (today - timedelta(days=days)).strftime("%Y-%m-%d")
    to_date = today.strftime("%Y-%m-%d")
    return label, from_date, to_date, days


# ============================================================
# メイン処理
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="脅威情報自動収集ツール")
    parser.add_argument("--period", choices=["daily", "weekly", "custom"], default="daily",
                        help="収集期間（daily=過去1日, weekly=過去7日, custom=--daysで指定）")
    parser.add_argument("--days", type=int, default=None,
                        help="customの場合の日数")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH,
                        help="設定ファイルパス")
    args = parser.parse_args()

    # 設定読込
    config = load_config(args.config)

    # ログ初期化
    log_dir = SCRIPT_DIR / config.get("paths", {}).get("logs_dir", "logs")
    logger = setup_logger(log_dir)
    logger.info("=" * 60)
    logger.info("脅威情報自動収集ツール 起動")
    logger.info("=" * 60)

    # 期間計算
    try:
        period_label, from_date, to_date, days = calc_period(args.period, args.days)
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)

    logger.info(f"収集期間: {from_date} 〜 {to_date}（{period_label}）")

    # ディレクトリ準備
    db_path = SCRIPT_DIR / config.get("paths", {}).get("db_path", "db/threats.sqlite")
    reports_dir = SCRIPT_DIR / config.get("paths", {}).get("reports_dir", "reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    # DB・コレクター初期化
    db = ThreatDB(db_path)
    collector = ThreatCollector(
        model_name=config["api"]["model"],  # model= ではなく model_name= に修正
        max_tokens=config["api"].get("max_tokens", 4000),
        logger=logger,
    )

    keywords = config.get("keywords", [])
    max_items = config.get("max_items_per_keyword", 30)

    if not keywords:
        logger.error("config.yaml にキーワードが設定されていません")
        sys.exit(1)

    logger.info(f"対象キーワード: {len(keywords)}件 / キーワードあたり最大{max_items}件")

    # 収集ループ
    run_started_at = datetime.now().isoformat(timespec="seconds")
    today_str = datetime.now().strftime("%Y-%m-%d")
    total_new = 0
    total_errors = 0
    total_dup = 0      # ← 【修正】ここを初期化することで UnboundLocalError を防ぎます
    error_keywords = []

    for i, kw in enumerate(keywords):
        if db.is_already_done(kw, today_str):
            logger.info(f"[スキップ] {kw} は本日既に収集済みです。")
            continue

        # --- 15 RPM 制限対策: キーワード切り替え時も 10秒待機 ---
        # 最初のキーワード以外で、実際に API を叩く前に待機
        if i > 0:
            time.sleep(10)

        logger.info(f"[収集] {kw}")
        try:
            items = collector.collect(kw, from_date, to_date, max_items)
            # collector.collect 内部で例外が発生すれば except ブロックへ飛ぶ
            items = collector.collect(kw, from_date, to_date, max_items)
            
            new_in_kw = 0
            for item in items:
                if db.insert_if_new(item, kw):
                    new_in_kw += 1
                else:
                    total_dup += 1 # ← 重複（既存データ）をカウント
            
            total_new += new_in_kw
            
            # ここまで正常に来た場合のみ SUCCESS
            db.update_history(kw, today_str, "SUCCESS")
            logger.info(f"  └─ 完了: 新規 {new_in_kw}件")

        except Exception as e:
            # 500エラーやタイムアウト時はこちら
            total_errors += 1
            error_keywords.append(kw)
            db.update_history(kw, today_str, "ERROR", str(e))
            logger.error(f"  └─ 収集失敗（次回再試行対象）: {e}")

    # レポート生成に必要な情報を取得
    records = db.get_recent(run_started_at)
    
    # render_markdown の引数を 7つに合わせる（前回の修正を適用）
    md = render_markdown(records, period_label, from_date, to_date, 
                         total_new, total_errors, error_keywords)

    # ファイル出力
    suffix = {"daily": "daily", "weekly": "weekly", "custom": f"custom{days}d"}[args.period]
    report_filename = f"{datetime.now().strftime('%Y-%m-%d')}_{suffix}.md"
    report_path = reports_dir / report_filename
    report_path.write_text(md, encoding="utf-8")

    logger.info("-" * 60)
    # ここで全ての変数が定義されているので、もうエラーは出ません
    logger.info(f"完了: 新規 {total_new}件 / 重複 {total_dup}件 / エラー {total_errors}件")
    logger.info(f"レポート出力: {report_path}")
    logger.info("=" * 60)

    db.close()


if __name__ == "__main__":
    main()
