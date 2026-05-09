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
from anthropic import Anthropic
from dotenv import load_dotenv
import google.generativeai as genai


# ============================================================
# 初期化
# ============================================================
load_dotenv()

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
        self.conn.executescript("""
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
        CREATE INDEX IF NOT EXISTS idx_collected_at ON threats(collected_at);
        CREATE INDEX IF NOT EXISTS idx_threat_level ON threats(threat_level);
        CREATE INDEX IF NOT EXISTS idx_publish_date ON threats(publish_date);
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

    def close(self):
        self.conn.close()


# ============================================================
# Claude APIクライアント
# ============================================================
class ThreatCollector:
    def __init__(self, model_name: str, max_tokens: int, logger: logging.Logger):
        # GitHub Secrets から読み取った GOOGLE_API_KEY を使用
        api_key = os.getenv("GOOGLE_API_KEY")
        if not api_key:
            raise RuntimeError("GOOGLE_API_KEY が設定されていません")
        
        genai.configure(api_key=api_key)
        
        # Google検索ツールを有効化してモデルを初期化
        self.model = genai.GenerativeModel(
            model_name=model_name,
            tools=[{'google_search_retrieval': {}}] 
        )
        self.max_tokens = max_tokens
        self.logger = logger

    def collect(self, keyword: str, from_date: str, to_date: str, max_items: int) -> list:
        """1キーワードについて、指定期間の脅威情報を収集する。
        max_itemsが大きい場合は複数回に分けて呼び出す。"""
        all_items = []
        # 1回あたり最大10件、必要分まで繰り返す
        batch_size = 10
        rounds = max(1, (max_items + batch_size - 1) // batch_size)

        for r in range(rounds):
            remaining = max_items - len(all_items)
            if remaining <= 0:
                break
            n = min(batch_size, remaining)

            # 既出を除外する指示
            seen_titles = [it.get("title", "") for it in all_items]
            exclude_block = ""
            if seen_titles:
                exclude_block = (
                    "\nDO NOT include items whose title matches any of the following "
                    "(already collected in this run):\n- "
                    + "\n- ".join(seen_titles[-20:])  # 直近20件のみ送る
                    + "\n"
                )

            prompt = self._build_prompt(keyword, from_date, to_date, n, exclude_block)
            self.logger.info(f"  └─ Round {r + 1}/{rounds}: {n}件を要求")

            try:
                items = self._call_api(prompt)
            except Exception as e:
                self.logger.warning(f"  └─ API呼び出し失敗: {e}")
                break

            if not items:
                self.logger.info("  └─ これ以上情報が得られませんでした")
                break

            # 期間外を除外
            items = self._filter_by_date(items, from_date, to_date)
            all_items.extend(items)

            # 短いウェイト（レート制限対策）
            if r < rounds - 1:
                time.sleep(2)

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
        # Gemini APIの呼び出し
        response = self.model.generate_content(
            prompt,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=self.max_tokens,
                temperature=0.1, # 抽出精度のため低めに設定
            )
        )

        # JSON抽出処理 (GeminiはMarkdownで返してくることがあるため)
        text = response.text

        # JSON抽出
        cleaned = re.sub(r"```json|```", "", text).strip()
        start = cleaned.find("[")
        end = cleaned.rfind("]")
        if start == -1 or end == -1 or end < start:
            return []
        json_str = cleaned[start:end + 1]

        # パース（壊れていれば末尾修復）
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            last_brace = json_str.rfind("}")
            if last_brace == -1:
                return []
            try:
                return json.loads(json_str[:last_brace + 1] + "]")
            except json.JSONDecodeError:
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
                    new_count: int, dup_count: int) -> str:
    lines = []
    today = datetime.now().strftime("%Y-%m-%d")

    lines.append(f"# 脅威情報レポート {today}")
    lines.append("")
    lines.append(f"**収集期間：** {from_date} 〜 {to_date}（{period_label}）")
    lines.append(f"**新規検出：** {new_count}件 / 全収集：{new_count + dup_count}件（重複{dup_count}件除外）")
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
    total_new = 0
    total_dup = 0

    for kw in keywords:
        logger.info(f"[収集] {kw}")
        try:
            items = collector.collect(kw, from_date, to_date, max_items)
        except Exception as e:
            logger.error(f"  └─ エラー: {e}")
            continue

        new_in_kw = 0
        dup_in_kw = 0
        for item in items:
            if db.insert_if_new(item, kw):
                new_in_kw += 1
            else:
                dup_in_kw += 1
        total_new += new_in_kw
        total_dup += dup_in_kw
        logger.info(f"  └─ 新規 {new_in_kw}件 / 重複 {dup_in_kw}件")

    # 今回の実行で新規追加されたレコードのみを取得してレポート化
    records = db.get_recent(run_started_at)
    md = render_markdown(records, period_label, from_date, to_date, total_new, total_dup)

    # ファイル出力
    suffix = {"daily": "daily", "weekly": "weekly", "custom": f"custom{days}d"}[args.period]
    report_filename = f"{datetime.now().strftime('%Y-%m-%d')}_{suffix}.md"
    report_path = reports_dir / report_filename
    report_path.write_text(md, encoding="utf-8")

    logger.info("-" * 60)
    logger.info(f"完了: 新規{total_new}件 / 重複{total_dup}件")
    logger.info(f"レポート出力: {report_path}")
    logger.info("=" * 60)

    db.close()


if __name__ == "__main__":
    main()
