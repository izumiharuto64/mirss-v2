"""
================================================================================
MiRSS - Misskey MiAuth連携 RSSリーダー (Python サーバー実装)
================================================================================
ブラウザ側の CORS 制限や localStorage 依存を解消するため、Python 側で以下を
統合処理するシングルファイルサーバーアプリケーションです。

主な機能:
1. SQLite データベースによるユーザー・MiAuthセッション・購読フィード・記事状態管理
2. サーバーサイドでの RSS 2.0 / Atom フィード取得・XMLパース（CORSプロキシ不要）
3. MiAuth 認証フローの開始・コールバック検証・トークン保存
4. Misskey API (`/api/notes/create`) 連携による記事シェア（ノート投稿）
5. ライトモード / ダークモード対応の Web UI（`/` に配信）および REST API

実行方法:
  pip install fastapi uvicorn httpx
  python main.py
  ブラウザで http://127.0.0.1:8000 にアクセスしてください。
================================================================================
"""

from __future__ import annotations

import base64
import html
import hashlib
import json
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlparse
import xml.etree.ElementTree as ET

import httpx
import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

# ==============================================================================
# 設定・定数
# ==============================================================================
APP_HOST = os.getenv("MIRSS_HOST", "127.0.0.1")
APP_PORT = int(os.getenv("MIRSS_PORT", "8000"))
BASE_URL = os.getenv("MIRSS_BASE_URL", f"http://{APP_HOST}:{APP_PORT}")
DB_PATH = os.getenv("MIRSS_DB_PATH", "mirss.db")
HTTP_TIMEOUT_SECONDS = float(os.getenv("MIRSS_HTTP_TIMEOUT", "12.0"))
# 任意の事前APIキー／固定トークン指定用スロット（環境変数 MIRSS_MIAUTH_API_KEY で設定可能）
MIAUTH_API_KEY = os.getenv("E1hyIdc6eh9hOzB9ZSH6mWJytl0MiPTC", "").strip()

# データベース排他制御用ロック
DB_LOCK = threading.Lock()
MIAUTH_API_KEY = os.getenv("E1hyIdc6eh9hOzB9ZSH6mWJytl0MiPTC", "").strip()


# ==============================================================================
# Pydantic リクエストモデル定義
# ==============================================================================
class MiAuthStartRequest(BaseModel):
    host: str = Field(..., min_length=1, max_length=255, description="Misskeyインスタンスのホスト名")
    api_key: str = Field(default="", max_length=512, description="任意のMiAuth APIキー / トークン")
    host: str = Field(default="misskey.io", max_length=255)


class FeedCreateRequest(BaseModel):
    user_key: str = Field(..., min_length=1)
    url: str = Field(..., min_length=1, max_length=2048)


class ArticleStateRequest(BaseModel):
    user_key: str = Field(..., min_length=1)
    article_id: str = Field(..., min_length=1)
    is_read: Optional[bool] = None
    is_starred: Optional[bool] = None


class MarkAllReadRequest(BaseModel):
    user_key: str = Field(..., min_length=1)
    filter_type: str = Field(default="all")


class ShareNoteRequest(BaseModel):
    user_key: str = Field(..., min_length=1)
    article_id: str = Field(..., min_length=1)
    comment: str = Field(default="", max_length=1000)


# ==============================================================================
# データベース管理クラス（SQLite）
# ==============================================================================
class DatabaseManager:
    """SQLiteを用いた永続化ストレージ層。"""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def _init_db(self) -> None:
        """必要なテーブルが存在しない場合に作成する。"""
        with DB_LOCK:
            with self._connect() as conn:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                        user_key TEXT PRIMARY KEY,
                        misskey_user_id TEXT NOT NULL,
                        username TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        host TEXT NOT NULL,
                        avatar_url TEXT NOT NULL,
                        access_token TEXT NOT NULL,
                        is_demo INTEGER NOT NULL DEFAULT 0,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS miauth_sessions (
                        session_id TEXT PRIMARY KEY,
                        host TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'pending',
                        user_key TEXT,
                        created_at TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS feeds (
                        id TEXT PRIMARY KEY,
                        user_key TEXT NOT NULL,
                        title TEXT NOT NULL,
                        url TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        UNIQUE(user_key, url),
                        FOREIGN KEY(user_key) REFERENCES users(user_key) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS articles (
                        id TEXT PRIMARY KEY,
                        user_key TEXT NOT NULL,
                        feed_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        link TEXT NOT NULL,
                        description TEXT NOT NULL,
                        pub_date TEXT NOT NULL,
                        is_read INTEGER NOT NULL DEFAULT 0,
                        is_starred INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY(user_key) REFERENCES users(user_key) ON DELETE CASCADE,
                        FOREIGN KEY(feed_id) REFERENCES feeds(id) ON DELETE CASCADE
                    );
                    """
                )

    def create_miauth_session(self, session_id: str, host: str) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with DB_LOCK:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO miauth_sessions (session_id, host, status, created_at)
                    VALUES (?, ?, 'pending', ?)
                    """,
                    (session_id, host, now),
                )

    def get_miauth_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with DB_LOCK:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM miauth_sessions WHERE session_id = ?",
                    (session_id,),
                ).fetchone()
                return dict(row) if row else None

    def complete_miauth_session(self, session_id: str, user_key: str) -> None:
        with DB_LOCK:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE miauth_sessions
                    SET status = 'completed', user_key = ?
                    WHERE session_id = ?
                    """,
                    (user_key, session_id),
                )

    def upsert_user(
        self,
        *,
        misskey_user_id: str,
        username: str,
        display_name: str,
        host: str,
        avatar_url: str,
        access_token: str,
        is_demo: bool = False,
    ) -> Dict[str, Any]:
        """ユーザー情報を登録または更新し、アプリ内部の user_key を返す。"""
        user_key = f"{username}@{host}"
        now = datetime.now(timezone.utc).isoformat()
        demo_flag = 1 if is_demo else 0

        with DB_LOCK:
            with self._connect() as conn:
                existing = conn.execute(
                    "SELECT created_at FROM users WHERE user_key = ?",
                    (user_key,),
                ).fetchone()

                if existing:
                    conn.execute(
                        """
                        UPDATE users
                        SET misskey_user_id = ?, username = ?, display_name = ?,
                            host = ?, avatar_url = ?, access_token = ?,
                            is_demo = ?, updated_at = ?
                        WHERE user_key = ?
                        """,
                        (
                            misskey_user_id,
                            username,
                            display_name,
                            host,
                            avatar_url,
                            access_token,
                            demo_flag,
                            now,
                            user_key,
                        ),
                    )
                else:
                    conn.execute(
                        """
                        INSERT INTO users (
                            user_key, misskey_user_id, username, display_name,
                            host, avatar_url, access_token, is_demo,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user_key,
                            misskey_user_id,
                            username,
                            display_name,
                            host,
                            avatar_url,
                            access_token,
                            demo_flag,
                            now,
                            now,
                        ),
                    )

        user = self.get_user(user_key)
        if not user:
            raise RuntimeError("ユーザー情報の保存後に取得できませんでした")

        # 新規ユーザーの場合は初期サンプルフィード・記事を投入
        if not self.get_feeds(user_key):
            self._seed_initial_data(user_key)

        return user

    def get_user(self, user_key: str) -> Optional[Dict[str, Any]]:
        with DB_LOCK:
            with self._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM users WHERE user_key = ?",
                    (user_key,),
                ).fetchone()
                if not row:
                    return None
                data = dict(row)
                data["is_demo"] = bool(data["is_demo"])
                return data

    def _seed_initial_data(self, user_key: str) -> None:
        """初回ログイン・登録ユーザー向けの初期フィードと記事を作成。"""
        now_ts = datetime.now(timezone.utc).timestamp()
        sample_feeds = [
            ("feed_zenn", "Zenn トレンド", "https://zenn.dev/feed"),
            ("feed_misskey", "Misskey Hub お知らせ", "https://misskey-hub.net/feed.xml"),
        ]
        sample_articles = [
            (
                "art_welcome_1",
                "feed_misskey",
                "MiRSS（Python版）へようこそ！サーバー側でRSSを取得・管理します",
                "https://misskey-hub.net/",
                "ブラウザのCORSプロキシに頼らず、Pythonサーバーが直接RSS/Atomフィードを取得してSQLiteに保存します。MiAuthで連携したMisskeyアカウントからそのままノート投稿も可能です。",
                datetime.fromtimestamp(now_ts - 1800, tz=timezone.utc).isoformat(),
                0,
                1,
            ),
            (
                "art_welcome_2",
                "feed_zenn",
                "Python (FastAPI + SQLite) と Misskey MiAuth によるWebアプリ構築",
                "https://zenn.dev/",
                "MiAuthのセッション生成からコールバック検証、アクセストークンを使った /api/notes/create 呼び出しまでをPythonバックエンドで一貫して処理する構成です。",
                datetime.fromtimestamp(now_ts - 7200, tz=timezone.utc).isoformat(),
                0,
                0,
            ),
        ]

        now_iso = datetime.now(timezone.utc).isoformat()
        with DB_LOCK:
            with self._connect() as conn:
                for fid, title, url in sample_feeds:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO feeds (id, user_key, title, url, created_at)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (f"{user_key}:{fid}", user_key, title, url, now_iso),
                    )
                for aid, fid, title, link, desc, pub_date, is_read, is_starred in sample_articles:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO articles (
                            id, user_key, feed_id, title, link, description,
                            pub_date, is_read, is_starred
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"{user_key}:{aid}",
                            user_key,
                            f"{user_key}:{fid}",
                            title,
                            link,
                            desc,
                            pub_date,
                            is_read,
                            is_starred,
                        ),
                    )

    def get_feeds(self, user_key: str) -> List[Dict[str, Any]]:
        with DB_LOCK:
            with self._connect() as conn:
                rows = conn.execute(
                    "SELECT id, title, url, created_at FROM feeds WHERE user_key = ? ORDER BY created_at ASC",
                    (user_key,),
                ).fetchall()
                return [dict(r) for r in rows]

    def add_feed(self, user_key: str, title: str, url: str) -> Dict[str, Any]:
        feed_id = f"{user_key}:feed_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()
        with DB_LOCK:
            with self._connect() as conn:
                existing = conn.execute(
                    "SELECT id, title, url, created_at FROM feeds WHERE user_key = ? AND url = ?",
                    (user_key, url),
                ).fetchone()
                if existing:
                    raise ValueError("このフィードURLはすでに登録されています。")

                conn.execute(
                    """
                    INSERT INTO feeds (id, user_key, title, url, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (feed_id, user_key, title, url, now),
                )
                row = conn.execute(
                    "SELECT id, title, url, created_at FROM feeds WHERE id = ?",
                    (feed_id,),
                ).fetchone()
                return dict(row)

    def delete_feed(self, user_key: str, feed_id: str) -> bool:
        with DB_LOCK:
            with self._connect() as conn:
                cur = conn.execute(
                    "DELETE FROM feeds WHERE user_key = ? AND id = ?",
                    (user_key, feed_id),
                )
                return cur.rowcount > 0

    def upsert_articles(self, user_key: str, feed_id: str, parsed_items: List[Dict[str, str]]) -> int:
        """新規記事のみを挿入し、追加件数を返す。"""
        added_count = 0
        with DB_LOCK:
            with self._connect() as conn:
                for item in parsed_items:
                    raw_uid = item.get("guid") or item.get("link") or item.get("title") or uuid.uuid4().hex
                    digest = hashlib.sha256(f"{feed_id}:{raw_uid}".encode("utf-8")).hexdigest()[:24]
                    article_id = f"{user_key}:art_{digest}"

                    exists = conn.execute(
                        "SELECT 1 FROM articles WHERE id = ?",
                        (article_id,),
                    ).fetchone()

                    if not exists:
                        conn.execute(
                            """
                            INSERT INTO articles (
                                id, user_key, feed_id, title, link, description,
                                pub_date, is_read, is_starred
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)
                            """,
                            (
                                article_id,
                                user_key,
                                feed_id,
                                item.get("title", "無題の記事"),
                                item.get("link", ""),
                                item.get("description", ""),
                                item.get("pub_date", datetime.now(timezone.utc).isoformat()),
                            ),
                        )
                        added_count += 1
        return added_count

    def get_articles(self, user_key: str) -> List[Dict[str, Any]]:
        with DB_LOCK:
            with self._connect() as conn:
                rows = conn.execute(
                    """
                    SELECT id, feed_id, title, link, description, pub_date, is_read, is_starred
                    FROM articles
                    WHERE user_key = ?
                    ORDER BY pub_date DESC
                    """,
                    (user_key,),
                ).fetchall()
                result = []
                for r in rows:
                    d = dict(r)
                    d["is_read"] = bool(d["is_read"])
                    d["is_starred"] = bool(d["is_starred"])
                    result.append(d)
                return result

    def get_article(self, user_key: str, article_id: str) -> Optional[Dict[str, Any]]:
        with DB_LOCK:
            with self._connect() as conn:
                row = conn.execute(
                    """
                    SELECT id, feed_id, title, link, description, pub_date, is_read, is_starred
                    FROM articles
                    WHERE user_key = ? AND id = ?
                    """,
                    (user_key, article_id),
                ).fetchone()
                if not row:
                    return None
                d = dict(row)
                d["is_read"] = bool(d["is_read"])
                d["is_starred"] = bool(d["is_starred"])
                return d

    def update_article_flags(
        self,
        user_key: str,
        article_id: str,
        *,
        is_read: Optional[bool] = None,
        is_starred: Optional[bool] = None,
    ) -> Optional[Dict[str, Any]]:
        current = self.get_article(user_key, article_id)
        if not current:
            return None

        next_read = 1 if (is_read if is_read is not None else current["is_read"]) else 0
        next_starred = 1 if (is_starred if is_starred is not None else current["is_starred"]) else 0

        with DB_LOCK:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE articles
                    SET is_read = ?, is_starred = ?
                    WHERE user_key = ? AND id = ?
                    """,
                    (next_read, next_starred, user_key, article_id),
                )
        return self.get_article(user_key, article_id)

    def mark_all_as_read(self, user_key: str, filter_type: str = "all") -> int:
        with DB_LOCK:
            with self._connect() as conn:
                if filter_type in ("all", "unread"):
                    cur = conn.execute(
                        "UPDATE articles SET is_read = 1 WHERE user_key = ? AND is_read = 0",
                        (user_key,),
                    )
                elif filter_type == "starred":
                    cur = conn.execute(
                        "UPDATE articles SET is_read = 1 WHERE user_key = ? AND is_starred = 1 AND is_read = 0",
                        (user_key,),
                    )
                else:
                    cur = conn.execute(
                        "UPDATE articles SET is_read = 1 WHERE user_key = ? AND feed_id = ? AND is_read = 0",
                        (user_key, filter_type),
                    )
                return cur.rowcount


db = DatabaseManager(DB_PATH)


# ==============================================================================
# RSS / Atom フィード取得・パース処理（サーバーサイド）
# ==============================================================================
def _clean_html_text(raw_html: str) -> str:
    """HTMLタグと余分な空白を除去してプレーンテキストにする。"""
    if not raw_html:
        return ""
    no_tags = re.sub(r"<[^>]+>", " ", raw_html)
    unescaped = html.unescape(no_tags)
    return re.sub(r"\s+", " ", unescaped).strip()


def _parse_iso_date(date_str: Optional[str]) -> str:
    """RSS/Atom の日付文字列を ISO 8601 (UTC) に正規化する。"""
    if not date_str:
        return datetime.now(timezone.utc).isoformat()
    cleaned = date_str.strip()
    try:
        # Python 3.11+ の fromisoformat は多くの形式を解釈可能
        dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except ValueError:
        pass

    # RFC 2822 / 一般的なRSS日付フォーマットを順次試行
    from email.utils import parsedate_to_datetime

    try:
        dt = parsedate_to_datetime(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return datetime.now(timezone.utc).isoformat()


def _local_name(tag: str) -> str:
    """XML名前空間 `{namespace}tag` からローカルタグ名を抽出する。"""
    return tag.split("}", 1)[-1].lower() if "}" in tag else tag.lower()


def _find_child_text(element: ET.Element, candidate_names: List[str]) -> str:
    """子要素から候補タグ名（名前空間無視）に一致するテキストを取得する。"""
    target_set = {n.lower() for n in candidate_names}
    for child in element:
        if _local_name(child.tag) in target_set:
            text = "".join(child.itertext()).strip()
            if text:
                return text
    return ""


async def fetch_and_parse_feed(feed_url: str) -> Dict[str, Any]:
    """HTTPでRSS/Atomフィードを取得し、フィード名と記事リストを返す。"""
    parsed_url = urlparse(feed_url)
    if parsed_url.scheme not in ("http", "https") or not parsed_url.netloc:
        raise ValueError("有効な http:// または https:// のURLを指定してください。")

    headers = {
        "User-Agent": "MiRSS-Python-FeedReader/1.0 (+https://github.com/misskey-dev/misskey)",
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    }

    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True) as client:
        resp = await client.get(feed_url, headers=headers)
        resp.raise_for_status()
        xml_bytes = resp.content

    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError("RSS / Atom XML の解析に失敗しました。") from exc

    root_tag = _local_name(root.tag)
    items: List[Dict[str, str]] = []
    feed_title = ""

    if root_tag == "feed":
        # Atom フィード
        feed_title = _find_child_text(root, ["title"]) or feed_url
        for entry in root:
            if _local_name(entry.tag) != "entry" or len(items) >= 20:
                continue
            title = _find_child_text(entry, ["title"]) or "無題の記事"
            link = ""
            for child in entry:
                if _local_name(child.tag) == "link":
                    rel = child.attrib.get("rel", "alternate")
                    href = child.attrib.get("href", "").strip()
                    if href and (rel == "alternate" or not link):
                        link = href
            summary_raw = _find_child_text(entry, ["summary", "content"])
            updated_raw = _find_child_text(entry, ["updated", "published"])
            guid = _find_child_text(entry, ["id"]) or link or title

            desc_clean = _clean_html_text(summary_raw)
            if len(desc_clean) > 450:
                desc_clean = desc_clean[:450] + "..."

            items.append(
                {
                    "guid": guid,
                    "title": title,
                    "link": link,
                    "description": desc_clean,
                    "pub_date": _parse_iso_date(updated_raw),
                }
            )
    else:
        # RSS 2.0 / RSS 1.0 (RDF)
        channel = None
        if root_tag == "rss":
            for child in root:
                if _local_name(child.tag) == "channel":
                    channel = child
                    break
        elif root_tag == "rdf":
            for child in root:
                if _local_name(child.tag) == "channel":
                    channel = child
                    break

        container = channel if channel is not None else root
        feed_title = _find_child_text(container, ["title"]) or feed_url

        item_elements: List[ET.Element] = []
        for elem in root.iter():
            if _local_name(elem.tag) == "item":
                item_elements.append(elem)
                if len(item_elements) >= 20:
                    break

        for item_el in item_elements:
            title = _find_child_text(item_el, ["title"]) or "無題の記事"
            link = _find_child_text(item_el, ["link"])
            desc_raw = _find_child_text(item_el, ["encoded", "description", "summary"])
            pub_raw = _find_child_text(item_el, ["pubDate", "date"])
            guid = _find_child_text(item_el, ["guid"]) or link or title

            desc_clean = _clean_html_text(desc_raw)
            if len(desc_clean) > 450:
                desc_clean = desc_clean[:450] + "..."

            items.append(
                {
                    "guid": guid,
                    "title": title,
                    "link": link,
                    "description": desc_clean,
                    "pub_date": _parse_iso_date(pub_raw),
                }
            )

    return {"title": feed_title, "items": items}


# ==============================================================================
# Misskey MiAuth & API クライアント
# ==============================================================================
def normalize_misskey_host(raw_host: str) -> str:
    cleaned = raw_host.strip().lower()
    cleaned = re.sub(r"^https?://", "", cleaned)
    cleaned = cleaned.split("/", 1)[0].strip()
    if not cleaned or not re.match(r"^[a-z0-9.-]+(:\d+)?$", cleaned):
        raise ValueError("有効なMisskeyインスタンスのホスト名を入力してください。")
    return cleaned


async def verify_miauth_session(host: str, session_id: str) -> Dict[str, Any]:
    """POST https://{host}/api/miauth/{session}/check を呼び出して認証結果を検証する。"""
    url = f"https://{host}/api/miauth/{quote(session_id)}/check"
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.post(url, json={})
        resp.raise_for_status()
        data = resp.json()

    if not isinstance(data, dict) or not data.get("ok") or not data.get("user") or not data.get("token"):
        raise ValueError("MiAuthの認証が完了していないか、拒否されました。")

    user_obj = data["user"]
    username = user_obj.get("username") or "user"
    display_name = user_obj.get("name") or username
    avatar_url = (
        user_obj.get("avatarUrl")
        or f"https://placehold.co/80x80/86b300/ffffff?text={quote(username[0].upper())}"
    )

    return db.upsert_user(
        misskey_user_id=str(user_obj.get("id", username)),
        username=str(username),
        display_name=str(display_name),
        host=host,
        avatar_url=str(avatar_url),
        access_token=str(data["token"]),
        is_demo=False,
    )


async def create_misskey_note(user: Dict[str, Any], text: str) -> Dict[str, Any]:
    """Misskey API `/api/notes/create` を使ってノートを投稿する。"""
    if user.get("is_demo"):
        return {"ok": True, "demo": True, "createdNote": {"text": text}}

    url = f"https://{user['host']}/api/notes/create"
    payload = {
        "i": user["access_token"],
        "text": text,
    }
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
        resp = await client.post(url, json=payload)
        resp.raise_for_status()
        return resp.json()


# ==============================================================================
# Web UI HTML（ライトモード / ダークモード対応）
# ==============================================================================
FRONTEND_HTML = """<!DOCTYPE html>
<html lang="ja" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MiRSS - Misskey連携 RSSリーダー (Python Edition)</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Noto+Sans+JP:wght@400;500;700&display=swap" rel="stylesheet">
    <script src="https://unpkg.com/lucide@latest"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Inter', 'Noto Sans JP', 'sans-serif'],
                    },
                    colors: {
                        misskey: {
                            DEFAULT: '#86b300',
                            hover: '#739900',
                            light: '#a3d900',
                            bg: '#16171a',
                            panel: '#1f2125',
                            border: '#2e3138',
                            lightBg: '#f4f6f8',
                            lightPanel: '#ffffff',
                            lightBorder: '#e2e8f0'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: rgba(148, 163, 184, 0.35); border-radius: 9999px; }
        ::-webkit-scrollbar-thumb:hover { background: rgba(148, 163, 184, 0.55); }
    </style>
</head>
<body class="bg-misskey-lightBg text-slate-800 dark:bg-misskey-bg dark:text-slate-100 min-h-screen flex flex-col antialiased transition-colors duration-200">

    <!-- 通知トースト -->
    <div id="toast-container" class="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full pointer-events-none px-4 sm:px-0"></div>

    <!-- ログイン / MiAuth 認証画面 -->
    <div id="auth-view" class="flex-1 flex flex-col items-center justify-center p-4 relative">
        <div class="absolute top-4 right-4 sm:top-6 sm:right-6">
            <div class="inline-flex items-center p-1 rounded-2xl bg-white dark:bg-misskey-panel border border-misskey-lightBorder dark:border-misskey-border shadow-sm">
                <button type="button" onclick="setTheme('light')" id="auth-theme-light" class="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition">
                    <i data-lucide="sun" class="w-3.5 h-3.5"></i>
                    <span>ライト</span>
                </button>
                <button type="button" onclick="setTheme('dark')" id="auth-theme-dark" class="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-semibold transition">
                    <i data-lucide="moon" class="w-3.5 h-3.5"></i>
                    <span>ダーク</span>
                </button>
            </div>
        </div>

        <div class="max-w-md w-full bg-misskey-lightPanel dark:bg-misskey-panel rounded-3xl shadow-xl border border-misskey-lightBorder dark:border-misskey-border p-6 sm:p-8">
            <div class="text-center mb-7">
                <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-misskey/15 text-misskey mb-4 ring-1 ring-misskey/20">
                    <i data-lucide="rss" class="w-8 h-8"></i>
                </div>
                <h1 class="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">MiRSS</h1>
                <p class="text-sm text-slate-500 dark:text-slate-400 mt-1">
                    Python (FastAPI + SQLite) バックエンド版 RSSリーダー
                </p>
            </div>

            <div id="auth-loading" class="hidden text-center py-8">
                <div class="inline-block animate-spin rounded-full h-10 w-10 border-4 border-misskey border-t-transparent mb-4"></div>
                <p class="font-medium text-slate-700 dark:text-slate-200">Misskeyの認証をサーバーで確認中...</p>
                <p class="text-xs text-slate-500 mt-1" id="auth-loading-host"></p>
            </div>

            <form id="miauth-form" class="space-y-5">
                <div>
                    <label for="instance-input" class="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                        Misskeyインスタンスのドメイン
                    </label>
                    <div class="relative">
                        <span class="absolute inset-y-0 left-0 pl-3.5 flex items-center text-slate-400 text-sm select-none font-medium">
                            https://
                        </span>
                        <input
                            type="text"
                            id="instance-input"
                            placeholder="misskey.io"
                            value="misskey.io"
                            required
                            class="w-full pl-16 pr-4 py-3 rounded-xl bg-slate-50 dark:bg-misskey-bg border border-slate-300 dark:border-misskey-border text-slate-900 dark:text-white focus:ring-2 focus:ring-misskey focus:border-misskey outline-none text-sm"
                        >
                    </div>
                    <div class="flex flex-wrap gap-1.5 mt-2.5">
                        <button type="button" onclick="setInstance('misskey.io')" class="text-xs px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-misskey-bg hover:bg-misskey/15 hover:text-misskey text-slate-600 dark:text-slate-400 font-medium">misskey.io</button>
                        <button type="button" onclick="setInstance('misskey.design')" class="text-xs px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-misskey-bg hover:bg-misskey/15 hover:text-misskey text-slate-600 dark:text-slate-400 font-medium">misskey.design</button>
                        <button type="button" onclick="setInstance('nijimiss.moe')" class="text-xs px-2.5 py-1 rounded-lg bg-slate-100 dark:bg-misskey-bg hover:bg-misskey/15 hover:text-misskey text-slate-600 dark:text-slate-400 font-medium">nijimiss.moe</button>
                    </div>
                </div>

                <div>
                    <label for="miauth-api-key-input" class="block text-sm font-semibold text-slate-700 dark:text-slate-300 mb-1.5">
                        MiAuth用 APIキー / トークン（任意）
                    </label>
                    <input
                        type="password"
                        id="miauth-api-key-input"
                        placeholder="未入力の場合はMiAuth認可後に自動取得されます"
                        class="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-misskey-bg border border-slate-300 dark:border-misskey-border text-slate-900 dark:text-white focus:ring-2 focus:ring-misskey focus:border-misskey outline-none text-sm"
                    >
                </div>

                <button
                    type="submit"
                    class="w-full py-3 px-4 rounded-xl bg-misskey hover:bg-misskey-hover text-white font-semibold shadow-md shadow-misskey/25 flex items-center justify-center gap-2 transition"
                >
                    <i data-lucide="log-in" class="w-5 h-5"></i>
                    <span>MiAuthでログイン / 登録</span>
                </button>
            </form>

            <div class="mt-6 pt-5 border-t border-slate-200 dark:border-misskey-border text-center">
                <p class="text-xs text-slate-500 dark:text-slate-400 mb-2.5">
                    ローカル検証やUI確認用アカウント
                </p>
                <button
                    type="button"
                    onclick="loginDemoMode()"
                    class="w-full py-2.5 px-4 rounded-xl border border-slate-300 dark:border-misskey-border bg-white dark:bg-misskey-bg/40 hover:bg-slate-50 dark:hover:bg-slate-800 text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center justify-center gap-2 transition"
                >
                    <i data-lucide="sparkles" class="w-4 h-4 text-misskey"></i>
                    <span>デモアカウントでログイン</span>
                </button>
            </div>
        </div>
    </div>

    <!-- メインアプリ画面 -->
    <div id="app-view" class="hidden flex-1 flex flex-col h-screen overflow-hidden">
        <header class="h-16 bg-misskey-lightPanel dark:bg-misskey-panel border-b border-misskey-lightBorder dark:border-misskey-border px-4 flex items-center justify-between shrink-0 z-20">
            <div class="flex items-center gap-3">
                <button onclick="toggleSidebar()" class="lg:hidden p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300">
                    <i data-lucide="menu" class="w-5 h-5"></i>
                </button>
                <div class="flex items-center gap-2.5">
                    <div class="w-9 h-9 rounded-xl bg-misskey/15 text-misskey flex items-center justify-center">
                        <i data-lucide="rss" class="w-5 h-5"></i>
                    </div>
                    <span class="font-bold text-lg tracking-tight text-slate-900 dark:text-white hidden sm:inline">MiRSS</span>
                </div>
            </div>

            <div class="flex-1 max-w-md mx-3 sm:mx-4">
                <div class="relative">
                    <i data-lucide="search" class="w-4 h-4 absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400"></i>
                    <input
                        type="text"
                        id="search-input"
                        oninput="renderArticles()"
                        placeholder="記事タイトルや内容を検索..."
                        class="w-full pl-10 pr-4 py-2 rounded-xl bg-slate-100 dark:bg-misskey-bg border border-transparent focus:border-misskey focus:bg-white dark:focus:bg-misskey-bg text-slate-900 dark:text-white outline-none text-sm"
                    >
                </div>
            </div>

            <div class="flex items-center gap-2">
                <button onclick="refreshAllFeeds()" id="refresh-btn" title="すべてのフィードを更新" class="p-2.5 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 transition">
                    <i data-lucide="refresh-cw" class="w-5 h-5"></i>
                </button>

                <div class="flex items-center p-1 rounded-xl bg-slate-100 dark:bg-misskey-bg border border-slate-200/80 dark:border-misskey-border">
                    <button type="button" onclick="setTheme('light')" id="nav-theme-light" class="p-1.5 rounded-lg text-xs transition" aria-label="ライトモード">
                        <i data-lucide="sun" class="w-4 h-4"></i>
                    </button>
                    <button type="button" onclick="setTheme('dark')" id="nav-theme-dark" class="p-1.5 rounded-lg text-xs transition" aria-label="ダークモード">
                        <i data-lucide="moon" class="w-4 h-4"></i>
                    </button>
                </div>

                <div class="relative" id="user-menu-container">
                    <button onclick="toggleUserDropdown()" class="flex items-center gap-2 p-1.5 pr-3 rounded-xl bg-slate-50 dark:bg-misskey-bg/50 hover:bg-slate-100 dark:hover:bg-slate-800 border border-misskey-lightBorder dark:border-misskey-border">
                        <img id="user-avatar" src="https://placehold.co/64x64/86b300/ffffff?text=M" alt="Avatar" class="w-7 h-7 rounded-lg object-cover">
                        <div class="text-left hidden md:block">
                            <div id="user-name" class="text-xs font-bold text-slate-800 dark:text-slate-100 leading-tight max-w-[100px] truncate">User</div>
                            <div id="user-handle" class="text-[10px] text-slate-500 dark:text-slate-400 leading-tight max-w-[100px] truncate">@user@misskey.io</div>
                        </div>
                        <i data-lucide="chevron-down" class="w-3.5 h-3.5 text-slate-400"></i>
                    </button>

                    <div id="user-dropdown" class="hidden absolute right-0 mt-2 w-56 bg-misskey-lightPanel dark:bg-misskey-panel rounded-2xl shadow-xl border border-misskey-lightBorder dark:border-misskey-border py-2 z-50">
                        <div class="px-4 py-2.5 border-b border-slate-100 dark:border-misskey-border">
                            <p id="dropdown-name" class="text-sm font-bold text-slate-900 dark:text-white truncate">User</p>
                            <p id="dropdown-handle" class="text-xs text-slate-500 dark:text-slate-400 truncate">@user@misskey.io</p>
                            <span id="demo-badge" class="hidden inline-block mt-1.5 text-[10px] font-semibold px-2 py-0.5 rounded-full bg-misskey/15 text-misskey">デモモード</span>
                        </div>
                        <button onclick="openAddFeedModal(); toggleUserDropdown();" class="w-full text-left px-4 py-2.5 text-sm text-slate-700 dark:text-slate-200 hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-2.5">
                            <i data-lucide="plus-circle" class="w-4 h-4 text-misskey"></i>
                            <span>RSSフィードを追加</span>
                        </button>
                        <button onclick="logout()" class="w-full text-left px-4 py-2.5 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 flex items-center gap-2.5">
                            <i data-lucide="log-out" class="w-4 h-4"></i>
                            <span>ログアウト</span>
                        </button>
                    </div>
                </div>
            </div>
        </header>

        <div class="flex-1 flex overflow-hidden relative">
            <div id="sidebar-overlay" onclick="toggleSidebar()" class="hidden fixed inset-0 bg-slate-900/50 z-20 lg:hidden"></div>

            <aside id="sidebar" class="fixed lg:static inset-y-0 left-0 z-30 w-72 bg-misskey-lightPanel dark:bg-misskey-panel border-r border-misskey-lightBorder dark:border-misskey-border flex flex-col transform -translate-x-full lg:translate-x-0 transition-transform duration-200">
                <div class="p-4">
                    <button onclick="openAddFeedModal()" class="w-full py-2.5 px-4 rounded-xl bg-misskey hover:bg-misskey-hover text-white font-semibold text-sm flex items-center justify-center gap-2">
                        <i data-lucide="plus" class="w-4 h-4"></i>
                        <span>フィードを追加</span>
                    </button>
                </div>

                <div class="px-3 space-y-1">
                    <button onclick="selectFilter('all')" id="filter-all" class="filter-btn w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-semibold bg-misskey/15 text-misskey">
                        <div class="flex items-center gap-2.5">
                            <i data-lucide="layers" class="w-4 h-4"></i>
                            <span>すべての記事</span>
                        </div>
                        <span id="count-all" class="text-xs px-2 py-0.5 rounded-full bg-misskey/20 font-bold">0</span>
                    </button>
                    <button onclick="selectFilter('unread')" id="filter-unread" class="filter-btn w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800">
                        <div class="flex items-center gap-2.5">
                            <i data-lucide="circle-dot" class="w-4 h-4"></i>
                            <span>未読のみ</span>
                        </div>
                        <span id="count-unread" class="text-xs px-2 py-0.5 rounded-full bg-slate-200 dark:bg-slate-700 font-semibold">0</span>
                    </button>
                    <button onclick="selectFilter('starred')" id="filter-starred" class="filter-btn w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800">
                        <div class="flex items-center gap-2.5">
                            <i data-lucide="star" class="w-4 h-4"></i>
                            <span>お気に入り</span>
                        </div>
                        <span id="count-starred" class="text-xs px-2 py-0.5 rounded-full bg-slate-200 dark:bg-slate-700 font-semibold">0</span>
                    </button>
                </div>

                <div class="px-6 pt-5 pb-2">
                    <span class="text-xs font-bold uppercase tracking-wider text-slate-400">購読中のフィード</span>
                </div>
                <div id="feed-list" class="flex-1 overflow-y-auto px-3 pb-4 space-y-1"></div>
            </aside>

            <main class="flex-1 flex flex-col overflow-hidden bg-misskey-lightBg dark:bg-misskey-bg">
                <div class="px-4 sm:px-6 py-3.5 bg-white/80 dark:bg-misskey-panel/80 backdrop-blur-md border-b border-misskey-lightBorder dark:border-misskey-border flex items-center justify-between shrink-0">
                    <div>
                        <h2 id="current-view-title" class="font-bold text-base sm:text-lg text-slate-900 dark:text-white">すべての記事</h2>
                        <p id="current-view-subtitle" class="text-xs text-slate-500 dark:text-slate-400">サーバーから取得した最新記事</p>
                    </div>
                    <button onclick="markAllAsRead()" class="text-xs sm:text-sm px-3 py-1.5 rounded-xl bg-white dark:bg-misskey-bg border border-slate-200 dark:border-misskey-border hover:bg-slate-50 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 font-medium flex items-center gap-1.5">
                        <i data-lucide="check-check" class="w-4 h-4 text-misskey"></i>
                        <span>すべて既読にする</span>
                    </button>
                </div>

                <div id="articles-container" class="flex-1 overflow-y-auto p-4 sm:p-6">
                    <div id="articles-grid" class="max-w-4xl mx-auto space-y-3"></div>
                </div>
            </main>
        </div>
    </div>

    <!-- フィード追加モーダル -->
    <div id="add-feed-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-xs">
        <div class="bg-misskey-lightPanel dark:bg-misskey-panel rounded-2xl max-w-md w-full p-6 border border-misskey-lightBorder dark:border-misskey-border shadow-2xl">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-bold flex items-center gap-2">
                    <i data-lucide="rss" class="w-5 h-5 text-misskey"></i>
                    <span>RSSフィードを追加</span>
                </h3>
                <button onclick="closeAddFeedModal()" class="p-1.5 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-500">
                    <i data-lucide="x" class="w-5 h-5"></i>
                </button>
            </div>
            <form id="add-feed-form" class="space-y-4">
                <div>
                    <label class="block text-sm font-semibold mb-1.5">RSS / Atom フィードURL</label>
                    <input type="url" id="feed-url-input" required placeholder="https://zenn.dev/feed" class="w-full px-3.5 py-2.5 rounded-xl bg-slate-50 dark:bg-misskey-bg border border-slate-300 dark:border-misskey-border outline-none text-sm">
                </div>
                <div class="flex flex-wrap gap-1.5">
                    <button type="button" onclick="fillFeedPreset('https://zenn.dev/feed')" class="text-xs px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-misskey-bg hover:bg-misskey/15 hover:text-misskey font-medium">Zenn トレンド</button>
                    <button type="button" onclick="fillFeedPreset('https://qiita.com/popular-items/feed')" class="text-xs px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-misskey-bg hover:bg-misskey/15 hover:text-misskey font-medium">Qiita 人気記事</button>
                    <button type="button" onclick="fillFeedPreset('https://b.hatena.ne.jp/hotentry/it.rss')" class="text-xs px-2.5 py-1.5 rounded-lg bg-slate-100 dark:bg-misskey-bg hover:bg-misskey/15 hover:text-misskey font-medium">はてブ IT</button>
                </div>
                <div class="flex justify-end gap-2 pt-2">
                    <button type="button" onclick="closeAddFeedModal()" class="px-4 py-2 rounded-xl text-sm hover:bg-slate-100 dark:hover:bg-slate-800">キャンセル</button>
                    <button type="submit" id="add-feed-submit-btn" class="px-5 py-2 rounded-xl bg-misskey hover:bg-misskey-hover text-white text-sm font-semibold">追加する</button>
                </div>
            </form>
        </div>
    </div>

    <!-- 記事詳細モーダル -->
    <div id="article-modal" class="hidden fixed inset-0 z-50 flex items-center justify-center p-2 sm:p-4 bg-slate-900/60 backdrop-blur-xs">
        <div class="bg-misskey-lightPanel dark:bg-misskey-panel rounded-2xl max-w-2xl w-full max-h-[90vh] flex flex-col border border-misskey-lightBorder dark:border-misskey-border shadow-2xl overflow-hidden">
            <div class="px-5 py-3.5 border-b border-misskey-lightBorder dark:border-misskey-border flex items-center justify-between shrink-0">
                <span id="modal-feed-title" class="text-xs font-bold px-2.5 py-1 rounded-lg bg-misskey/15 text-misskey truncate max-w-[200px]">Feed</span>
                <div class="flex items-center gap-1.5">
                    <button id="modal-star-btn" onclick="toggleCurrentModalStar()" class="p-2 rounded-xl hover:bg-slate-200/70 dark:hover:bg-slate-800 text-slate-500">
                        <i data-lucide="star" class="w-4 h-4"></i>
                    </button>
                    <a id="modal-external-link" href="#" target="_blank" rel="noopener noreferrer" class="p-2 rounded-xl hover:bg-slate-200/70 dark:hover:bg-slate-800 text-slate-500">
                        <i data-lucide="external-link" class="w-4 h-4"></i>
                    </a>
                    <button onclick="closeArticleModal()" class="p-2 rounded-xl hover:bg-slate-200/70 dark:hover:bg-slate-800 text-slate-500">
                        <i data-lucide="x" class="w-5 h-5"></i>
                    </button>
                </div>
            </div>
            <div class="p-5 sm:p-6 overflow-y-auto flex-1 space-y-4">
                <h1 id="modal-article-title" class="text-xl sm:text-2xl font-bold leading-snug">記事タイトル</h1>
                <div id="modal-article-date" class="text-xs text-slate-500 flex items-center gap-1"></div>
                <div id="modal-article-content" class="text-sm sm:text-base text-slate-700 dark:text-slate-300 leading-relaxed pt-3 border-t border-slate-100 dark:border-misskey-border"></div>
            </div>
            <div class="p-4 bg-slate-50 dark:bg-misskey-bg border-t border-misskey-lightBorder dark:border-misskey-border shrink-0">
                <div class="flex flex-col sm:flex-row gap-2">
                    <input type="text" id="misskey-note-comment" placeholder="感想を添えてMisskeyにノート..." class="flex-1 px-3.5 py-2 rounded-xl bg-white dark:bg-misskey-panel border border-slate-300 dark:border-misskey-border text-sm outline-none focus:ring-2 focus:ring-misskey">
                    <button onclick="shareToMisskey()" id="share-misskey-btn" class="px-4 py-2 rounded-xl bg-misskey hover:bg-misskey-hover text-white text-sm font-semibold flex items-center justify-center gap-2 shrink-0">
                        <i data-lucide="send" class="w-4 h-4"></i>
                        <span>Misskeyにノート</span>
                    </button>
                </div>
            </div>
        </div>
    </div>

    <script>
        const state = {
            user: null,
            feeds: [],
            articles: [],
            currentFilter: 'all',
            activeArticleId: null
        };

        const SESSION_KEY = 'mirss_py_user_key';
        const THEME_KEY = 'mirss_theme';

        window.addEventListener('DOMContentLoaded', async () => {
            initTheme();
            lucide.createIcons();

            const urlParams = new URLSearchParams(window.location.search);
            const sessionParam = urlParams.get('session');

            if (sessionParam) {
                await finishMiAuthCallback(sessionParam);
                return;
            }

            const savedKey = localStorage.getItem(SESSION_KEY);
            if (savedKey) {
                await loadUserState(savedKey);
                return;
            }

            showAuthView();
        });

        function initTheme() {
            const saved = localStorage.getItem(THEME_KEY);
            if (saved === 'light' || saved === 'dark') {
                setTheme(saved, false);
            } else {
                setTheme(window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light', false);
            }
        }

        function setTheme(mode, persist = true) {
            if (mode === 'dark') document.documentElement.classList.add('dark');
            else document.documentElement.classList.remove('dark');
            if (persist) localStorage.setItem(THEME_KEY, mode);
            updateThemeButtons(mode);
        }

        function updateThemeButtons(mode) {
            const al = document.getElementById('auth-theme-light');
            const ad = document.getElementById('auth-theme-dark');
            if (al && ad) {
                al.className = mode === 'light'
                    ? 'flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-misskey text-white'
                    : 'flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium text-slate-500';
                ad.className = mode === 'dark'
                    ? 'flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-misskey text-white'
                    : 'flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium text-slate-400';
            }
            const nl = document.getElementById('nav-theme-light');
            const nd = document.getElementById('nav-theme-dark');
            if (nl && nd) {
                nl.className = mode === 'light' ? 'p-1.5 rounded-lg text-xs bg-white text-amber-500 shadow-2xs' : 'p-1.5 rounded-lg text-xs text-slate-400';
                nd.className = mode === 'dark' ? 'p-1.5 rounded-lg text-xs bg-misskey-panel text-misskey shadow-2xs' : 'p-1.5 rounded-lg text-xs text-slate-500';
            }
        }

        function setInstance(domain) {
            document.getElementById('instance-input').value = domain;
        }

        document.getElementById('miauth-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const host = document.getElementById('instance-input').value.trim();
            const apiKey = document.getElementById('miauth-api-key-input').value.trim();
            try {
                const res = await fetch('/api/miauth/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host, api_key: apiKey })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'MiAuth開始エラー');
                showToast(`${data.host} の認証画面へ移動します...`, 'info');
                setTimeout(() => { window.location.href = data.auth_url; }, 350);
            } catch (err) {
                showToast(err.message, 'error');
            }
        });

        async function finishMiAuthCallback(sessionId) {
            document.getElementById('miauth-form').classList.add('hidden');
            document.getElementById('auth-loading').classList.remove('hidden');
            try {
                const res = await fetch('/api/miauth/callback', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId })
                });
                const data = await res.json();
                window.history.replaceState({}, document.title, window.location.pathname);
                if (!res.ok) throw new Error(data.detail || '認証検証に失敗しました');
                localStorage.setItem(SESSION_KEY, data.user.user_key);
                showToast(`ようこそ、${data.user.display_name} さん！`, 'success');
                await loadUserState(data.user.user_key);
            } catch (err) {
                document.getElementById('auth-loading').classList.add('hidden');
                document.getElementById('miauth-form').classList.remove('hidden');
                showToast(err.message, 'error');
            }
        }

        async function loginDemoMode() {
            try {
                const res = await fetch('/api/auth/demo', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ host: 'misskey.io' })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'デモログイン失敗');
                localStorage.setItem(SESSION_KEY, data.user.user_key);
                showToast('デモアカウントでログインしました', 'success');
                await loadUserState(data.user.user_key);
            } catch (err) {
                showToast(err.message, 'error');
            }
        }

        function logout() {
            localStorage.removeItem(SESSION_KEY);
            state.user = null;
            state.feeds = [];
            state.articles = [];
            document.getElementById('user-dropdown').classList.add('hidden');
            showAuthView();
        }

        function showAuthView() {
            document.getElementById('app-view').classList.add('hidden');
            document.getElementById('auth-view').classList.remove('hidden');
            document.getElementById('miauth-form').classList.remove('hidden');
            document.getElementById('auth-loading').classList.add('hidden');
        }

        async function loadUserState(userKey) {
            const res = await fetch(`/api/state?user_key=${encodeURIComponent(userKey)}`);
            if (!res.ok) {
                localStorage.removeItem(SESSION_KEY);
                showAuthView();
                return;
            }
            const data = await res.json();
            state.user = data.user;
            state.feeds = data.feeds;
            state.articles = data.articles;

            document.getElementById('auth-view').classList.add('hidden');
            document.getElementById('app-view').classList.remove('hidden');

            const handle = `@${state.user.username}@${state.user.host}`;
            document.getElementById('user-name').textContent = state.user.display_name;
            document.getElementById('user-handle').textContent = handle;
            document.getElementById('dropdown-name').textContent = state.user.display_name;
            document.getElementById('dropdown-handle').textContent = handle;
            document.getElementById('user-avatar').src = state.user.avatar_url;
            document.getElementById('demo-badge').classList.toggle('hidden', !state.user.is_demo);

            renderAll();
        }

        document.getElementById('add-feed-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            const urlInput = document.getElementById('feed-url-input');
            const btn = document.getElementById('add-feed-submit-btn');
            btn.disabled = true;
            btn.textContent = '取得中...';

            try {
                const res = await fetch('/api/feeds', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_key: state.user.user_key, url: urlInput.value.trim() })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'フィード追加失敗');
                urlInput.value = '';
                closeAddFeedModal();
                await loadUserState(state.user.user_key);
                showToast(`「${data.feed.title}」を追加しました（+${data.added_articles}件）`, 'success');
            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = '追加する';
            }
        });

        async function refreshAllFeeds() {
            if (!state.user) return;
            const btn = document.getElementById('refresh-btn');
            btn.classList.add('animate-spin', 'text-misskey');
            try {
                const res = await fetch('/api/feeds/refresh', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_key: state.user.user_key })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || '更新失敗');
                await loadUserState(state.user.user_key);
                showToast(data.added_articles > 0 ? `${data.added_articles}件の新着記事を取得しました` : '最新の状態です', 'success');
            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                btn.classList.remove('animate-spin', 'text-misskey');
            }
        }

        async function deleteFeed(feedId, event) {
            event.stopPropagation();
            const res = await fetch(`/api/feeds/${encodeURIComponent(feedId)}?user_key=${encodeURIComponent(state.user.user_key)}`, {
                method: 'DELETE'
            });
            if (res.ok) {
                if (state.currentFilter === feedId) state.currentFilter = 'all';
                await loadUserState(state.user.user_key);
                showToast('フィードを削除しました', 'info');
            }
        }

        function renderAll() {
            renderSidebar();
            renderArticles();
        }

        function renderSidebar() {
            document.getElementById('count-all').textContent = state.articles.length;
            document.getElementById('count-unread').textContent = state.articles.filter(a => !a.is_read).length;
            document.getElementById('count-starred').textContent = state.articles.filter(a => a.is_starred).length;

            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('bg-misskey/15', 'text-misskey', 'font-semibold');
                btn.classList.add('text-slate-600', 'dark:text-slate-300', 'hover:bg-slate-100', 'dark:hover:bg-slate-800', 'font-medium');
            });
            const activeBtn = document.getElementById(`filter-${state.currentFilter}`);
            if (activeBtn) {
                activeBtn.classList.add('bg-misskey/15', 'text-misskey', 'font-semibold');
                activeBtn.classList.remove('text-slate-600', 'dark:text-slate-300', 'hover:bg-slate-100', 'dark:hover:bg-slate-800', 'font-medium');
            }

            const feedList = document.getElementById('feed-list');
            feedList.innerHTML = '';
            state.feeds.forEach(feed => {
                const unread = state.articles.filter(a => a.feed_id === feed.id && !a.is_read).length;
                const isActive = state.currentFilter === feed.id;
                const div = document.createElement('div');
                div.onclick = () => selectFilter(feed.id);
                div.className = `group flex items-center justify-between px-3 py-2 rounded-xl text-sm cursor-pointer ${isActive ? 'bg-misskey/15 text-misskey font-semibold' : 'hover:bg-slate-100 dark:hover:bg-slate-800'}`;
                div.innerHTML = `
                    <div class="flex items-center gap-2.5 min-w-0 flex-1">
                        <i data-lucide="rss" class="w-3.5 h-3.5 shrink-0 ${isActive ? 'text-misskey' : 'text-slate-400'}"></i>
                        <span class="truncate">${escapeHtml(feed.title)}</span>
                    </div>
                    <div class="flex items-center gap-1.5 ml-2 shrink-0">
                        ${unread > 0 ? `<span class="text-xs px-1.5 py-0.5 rounded-full bg-misskey/20 text-misskey font-bold">${unread}</span>` : ''}
                        <button onclick="deleteFeed('${feed.id}', event)" class="opacity-0 group-hover:opacity-100 p-1 rounded-lg hover:bg-red-100 dark:hover:bg-red-900/40 text-slate-400 hover:text-red-500">
                            <i data-lucide="trash-2" class="w-3.5 h-3.5"></i>
                        </button>
                    </div>
                `;
                feedList.appendChild(div);
            });
            lucide.createIcons();
        }

        function renderArticles() {
            const q = document.getElementById('search-input').value.toLowerCase().trim();
            const list = state.articles.filter(a => {
                if (state.currentFilter === 'unread' && a.is_read) return false;
                if (state.currentFilter === 'starred' && !a.is_starred) return false;
                if (!['all', 'unread', 'starred'].includes(state.currentFilter) && a.feed_id !== state.currentFilter) return false;
                if (q && !a.title.toLowerCase().includes(q) && !a.description.toLowerCase().includes(q)) return false;
                return true;
            });

            const grid = document.getElementById('articles-grid');
            grid.innerHTML = '';
            if (list.length === 0) {
                grid.innerHTML = `<div class="text-center py-14 bg-misskey-lightPanel dark:bg-misskey-panel rounded-2xl border border-misskey-lightBorder dark:border-misskey-border text-slate-500">表示する記事がありません</div>`;
                return;
            }

            list.forEach(art => {
                const feed = state.feeds.find(f => f.id === art.feed_id);
                const card = document.createElement('article');
                card.onclick = () => openArticleModal(art.id);
                card.className = `group bg-misskey-lightPanel dark:bg-misskey-panel rounded-2xl p-4 sm:p-5 border cursor-pointer hover:shadow-md ${art.is_read ? 'border-misskey-lightBorder/70 dark:border-misskey-border/60 opacity-75' : 'border-misskey-lightBorder dark:border-misskey-border border-l-4 border-l-misskey'}`;
                card.innerHTML = `
                    <div class="flex items-start justify-between gap-3">
                        <div class="space-y-1.5 min-w-0 flex-1">
                            <div class="flex items-center gap-2 text-xs text-slate-500">
                                <span class="font-bold text-misskey truncate max-w-[180px]">${escapeHtml(feed ? feed.title : 'フィード')}</span>
                                <span>•</span>
                                <span>${escapeHtml(new Date(art.pub_date).toLocaleString('ja-JP'))}</span>
                            </div>
                            <h3 class="text-base sm:text-lg font-bold group-hover:text-misskey">${escapeHtml(art.title)}</h3>
                            <p class="text-xs sm:text-sm text-slate-600 dark:text-slate-400 line-clamp-2">${escapeHtml(art.description)}</p>
                        </div>
                        <div class="flex items-center gap-1 shrink-0">
                            <button onclick="toggleStar('${art.id}', event)" class="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 ${art.is_starred ? 'text-amber-400' : 'text-slate-400'}">
                                <i data-lucide="star" class="w-4 h-4 ${art.is_starred ? 'fill-amber-400' : ''}"></i>
                            </button>
                            <button onclick="toggleRead('${art.id}', event)" class="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-400 hover:text-misskey">
                                <i data-lucide="${art.is_read ? 'circle' : 'check-circle-2'}" class="w-4 h-4"></i>
                            </button>
                        </div>
                    </div>
                `;
                grid.appendChild(card);
            });
            lucide.createIcons();
        }

        function selectFilter(f) {
            state.currentFilter = f;
            renderAll();
        }

        async function patchArticle(articleId, payload) {
            const res = await fetch('/api/articles/state', {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_key: state.user.user_key, article_id: articleId, ...payload })
            });
            if (res.ok) {
                const updated = await res.json();
                const idx = state.articles.findIndex(a => a.id === articleId);
                if (idx !== -1) state.articles[idx] = updated.article;
                renderAll();
                return updated.article;
            }
            return null;
        }

        async function toggleRead(articleId, event) {
            if (event) event.stopPropagation();
            const current = state.articles.find(a => a.id === articleId);
            if (!current) return;
            await patchArticle(articleId, { is_read: !current.is_read });
        }

        async function toggleStar(articleId, event) {
            if (event) event.stopPropagation();
            const current = state.articles.find(a => a.id === articleId);
            if (!current) return;
            const updated = await patchArticle(articleId, { is_starred: !current.is_starred });
            if (updated && state.activeArticleId === articleId) updateModalStarIcon(updated.is_starred);
        }

        async function markAllAsRead() {
            const res = await fetch('/api/articles/mark-all-read', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user_key: state.user.user_key, filter_type: state.currentFilter })
            });
            if (res.ok) {
                await loadUserState(state.user.user_key);
                showToast('既読にしました', 'success');
            }
        }

        function openAddFeedModal() { document.getElementById('add-feed-modal').classList.remove('hidden'); }
        function closeAddFeedModal() { document.getElementById('add-feed-modal').classList.add('hidden'); }
        function fillFeedPreset(url) { document.getElementById('feed-url-input').value = url; }

        async function openArticleModal(articleId) {
            const art = state.articles.find(a => a.id === articleId);
            if (!art) return;
            state.activeArticleId = articleId;
            if (!art.is_read) await patchArticle(articleId, { is_read: true });

            const feed = state.feeds.find(f => f.id === art.feed_id);
            document.getElementById('modal-feed-title').textContent = feed ? feed.title : 'RSS';
            document.getElementById('modal-article-title').textContent = art.title;
            document.getElementById('modal-article-date').textContent = new Date(art.pub_date).toLocaleString('ja-JP');
            document.getElementById('modal-article-content').textContent = art.description || '本文サマリーはありません。';
            document.getElementById('modal-external-link').href = art.link || '#';
            document.getElementById('misskey-note-comment').value = '';
            updateModalStarIcon(art.is_starred);
            document.getElementById('article-modal').classList.remove('hidden');
            lucide.createIcons();
        }

        function closeArticleModal() {
            document.getElementById('article-modal').classList.add('hidden');
            state.activeArticleId = null;
        }

        function toggleCurrentModalStar() {
            if (state.activeArticleId) toggleStar(state.activeArticleId);
        }

        function updateModalStarIcon(starred) {
            const btn = document.getElementById('modal-star-btn');
            btn.className = starred ? 'p-2 rounded-xl hover:bg-slate-200/70 text-amber-400' : 'p-2 rounded-xl hover:bg-slate-200/70 text-slate-500';
            btn.innerHTML = `<i data-lucide="star" class="w-4 h-4 ${starred ? 'fill-amber-400' : ''}"></i>`;
            lucide.createIcons();
        }

        async function shareToMisskey() {
            if (!state.activeArticleId || !state.user) return;
            const comment = document.getElementById('misskey-note-comment').value.trim();
            const btn = document.getElementById('share-misskey-btn');
            btn.disabled = true;
            try {
                const res = await fetch('/api/misskey/note', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ user_key: state.user.user_key, article_id: state.activeArticleId, comment })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'ノート投稿失敗');
                document.getElementById('misskey-note-comment').value = '';
                showToast(data.demo ? '【デモ】Misskeyにノートしました' : `${state.user.host} にノートしました！`, 'success');
            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                btn.disabled = false;
            }
        }

        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('-translate-x-full');
            document.getElementById('sidebar-overlay').classList.toggle('hidden');
        }

        function toggleUserDropdown() {
            document.getElementById('user-dropdown').classList.toggle('hidden');
        }

        window.addEventListener('click', (e) => {
            const c = document.getElementById('user-menu-container');
            if (c && !c.contains(e.target)) document.getElementById('user-dropdown').classList.add('hidden');
        });

        function showToast(msg, type = 'info') {
            const container = document.getElementById('toast-container');
            const el = document.createElement('div');
            const palette = { success: 'bg-misskey text-white', error: 'bg-red-600 text-white', info: 'bg-slate-800 text-white' };
            el.className = `${palette[type] || palette.info} px-4 py-3 rounded-xl shadow-lg text-sm font-medium pointer-events-auto`;
            el.textContent = msg;
            container.appendChild(el);
            setTimeout(() => el.remove(), 3200);
        }

        function escapeHtml(s) {
            return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }
    </script>
</body>
</html>
"""


# ==============================================================================
# FastAPI アプリケーション・エンドポイント定義
# ==============================================================================
app = FastAPI(title="MiRSS Python Backend", version="1.0.0")


@app.get("/", response_class=HTMLResponse)
async def serve_index() -> HTMLResponse:
    """Webフロントエンド（ライト/ダークモードUI）を返す。"""
    return HTMLResponse(content=FRONTEND_HTML)


@app.get("/health")
async def health_check() -> Dict[str, str]:
    return {"status": "ok", "db": DB_PATH}


@app.post("/api/miauth/start")
async def miauth_start(req: MiAuthStartRequest) -> JSONResponse:
    """MiAuth セッションを発行し、Misskey 認可画面URLを返す。"""
    try:
        host = normalize_misskey_host(req.host)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # フォーム入力または環境変数 MIAUTH_API_KEY を受け取るスロット
    configured_api_key = req.api_key.strip() or MIAUTH_API_KEY

    session_id = str(uuid.uuid4())
    db.create_miauth_session(session_id=session_id, host=host)

    callback_url = quote(f"{BASE_URL}/?session={session_id}", safe="")
    app_name = quote("MiRSS (Python RSS Reader)", safe="")
    permissions = quote("read:account,write:notes", safe="")
    auth_url = (
        f"https://{host}/miauth/{session_id}"
        f"?name={app_name}&callback={callback_url}&permission={permissions}"
    )

    return JSONResponse(
        {
            "session_id": session_id,
            "host": host,
            "auth_url": auth_url,
            "has_api_key": bool(configured_api_key),
        }
    )


class MiAuthCallbackRequest(BaseModel):
    session_id: str = Field(..., min_length=1)


@app.post("/api/miauth/callback")
async def miauth_callback(req: MiAuthCallbackRequest) -> JSONResponse:
    """MiAuth コールバック後のセッションを検証し、ユーザーを登録・ログインさせる。"""
    session_row = db.get_miauth_session(req.session_id)
    if not session_row:
        raise HTTPException(status_code=404, detail="該当するMiAuthセッションが見つかりません。")

    host = session_row["host"]
    try:
        user = await verify_miauth_session(host=host, session_id=req.session_id)
        db.complete_miauth_session(session_id=req.session_id, user_key=user["user_key"])
        safe_user = {k: v for k, v in user.items() if k != "access_token"}
        return JSONResponse({"ok": True, "user": safe_user})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Misskeyインスタンスとの通信に失敗しました: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/api/auth/demo")
async def auth_demo(req: DemoLoginRequest) -> JSONResponse:
    """デモアカウントによるログイン／初期データ作成。"""
    try:
        host = normalize_misskey_host(req.host)
    except ValueError:
        host = "misskey.io"

    user = db.upsert_user(
        misskey_user_id="demo_py_001",
        username="misskey_cat",
        display_name="みすきーにゃんこ (Demo)",
        host=host,
        avatar_url="https://placehold.co/80x80/86b300/ffffff?text=Cat",
        access_token="demo_token_py",
        is_demo=True,
    )
    safe_user = {k: v for k, v in user.items() if k != "access_token"}
    return JSONResponse({"ok": True, "user": safe_user})


@app.get("/api/state")
async def get_state(user_key: str = Query(..., min_length=1)) -> JSONResponse:
    """ログイン中ユーザーのプロフィール・購読フィード・記事一覧を取得する。"""
    user = db.get_user(user_key)
    if not user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません。")

    safe_user = {k: v for k, v in user.items() if k != "access_token"}
    feeds = db.get_feeds(user_key)
    articles = db.get_articles(user_key)
    return JSONResponse({"user": safe_user, "feeds": feeds, "articles": articles})


@app.post("/api/feeds")
async def create_feed(req: FeedCreateRequest) -> JSONResponse:
    """RSS/Atom フィードをサーバー側で取得・検証し、DBへ追加する。"""
    user = db.get_user(req.user_key)
    if not user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません。")

    try:
        parsed = await fetch_and_parse_feed(req.url.strip())
        feed = db.add_feed(user_key=req.user_key, title=parsed["title"], url=req.url.strip())
        added_count = db.upsert_articles(
            user_key=req.user_key,
            feed_id=feed["id"],
            parsed_items=parsed["items"],
        )
        return JSONResponse({"ok": True, "feed": feed, "added_articles": added_count})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"フィードURLへの接続に失敗しました: {exc}") from exc


@app.post("/api/feeds/refresh")
async def refresh_feeds(payload: Dict[str, str]) -> JSONResponse:
    """登録済みすべてのフィードをサーバー側で再取得する。"""
    user_key = payload.get("user_key", "")
    user = db.get_user(user_key)
    if not user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません。")

    feeds = db.get_feeds(user_key)
    total_added = 0
    errors: List[str] = []

    for feed in feeds:
        try:
            parsed = await fetch_and_parse_feed(feed["url"])
            total_added += db.upsert_articles(
                user_key=user_key,
                feed_id=feed["id"],
                parsed_items=parsed["items"],
            )
        except Exception as exc:
            errors.append(f"{feed['title']}: {exc}")

    return JSONResponse({"ok": True, "added_articles": total_added, "errors": errors})


@app.delete("/api/feeds/{feed_id}")
async def remove_feed(feed_id: str, user_key: str = Query(..., min_length=1)) -> JSONResponse:
    deleted = db.delete_feed(user_key=user_key, feed_id=feed_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="フィードが見つかりません。")
    return JSONResponse({"ok": True})


@app.patch("/api/articles/state")
async def patch_article_state(req: ArticleStateRequest) -> JSONResponse:
    article = db.update_article_flags(
        user_key=req.user_key,
        article_id=req.article_id,
        is_read=req.is_read,
        is_starred=req.is_starred,
    )
    if not article:
        raise HTTPException(status_code=404, detail="記事が見つかりません。")
    return JSONResponse({"ok": True, "article": article})


@app.post("/api/articles/mark-all-read")
async def mark_all_read_endpoint(req: MarkAllReadRequest) -> JSONResponse:
    updated = db.mark_all_as_read(user_key=req.user_key, filter_type=req.filter_type)
    return JSONResponse({"ok": True, "updated_count": updated})


@app.post("/api/misskey/note")
async def share_article_note(req: ShareNoteRequest) -> JSONResponse:
    """対象記事の情報とコメントを Misskey にノート投稿する。"""
    user = db.get_user(req.user_key)
    if not user:
        raise HTTPException(status_code=404, detail="ユーザーが見つかりません。")

    article = db.get_article(req.user_key, req.article_id)
    if not article:
        raise HTTPException(status_code=404, detail="記事が見つかりません。")

    parts = []
    if req.comment.strip():
        parts.append(req.comment.strip())
    parts.append(article["title"])
    if article["link"]:
        parts.append(article["link"])
    note_text = "\n\n".join(parts)

    try:
        result = await create_misskey_note(user=user, text=note_text)
        return JSONResponse({"ok": True, "demo": bool(user.get("is_demo")), "result": result})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Misskey APIへの投稿に失敗しました: {exc}") from exc


if __name__ == "__main__":
    print(f"MiRSS Python Server starting on {BASE_URL} (DB: {DB_PATH})")
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)
