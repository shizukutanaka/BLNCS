"""
Log Search System
ログ検索・フィルタ機能
"""

import os
import re
import json
import time
import logging
from typing import Dict, List, Any, Optional, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """ログエントリ"""
    timestamp: str
    level: str
    logger: str
    message: str
    file_path: str
    line_number: int


class LogSearcher:
    """ログ検索システム"""

    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']

    def search_logs(self,
                   query: str = "",
                   level: Optional[str] = None,
                   start_time: Optional[datetime] = None,
                   end_time: Optional[datetime] = None,
                   limit: int = 100) -> List[LogEntry]:
        """ログ検索"""
        results = []

        if not self.log_dir.exists():
            return results

        # ログファイル一覧取得
        log_files = list(self.log_dir.glob("*.log"))
        log_files.extend(self.log_dir.glob("*.log.*"))

        for log_file in sorted(log_files, key=lambda x: x.stat().st_mtime, reverse=True):
            if len(results) >= limit:
                break

            file_results = self._search_file(
                log_file, query, level, start_time, end_time, limit - len(results)
            )
            results.extend(file_results)

        return sorted(results, key=lambda x: x.timestamp, reverse=True)[:limit]

    def _search_file(self,
                    file_path: Path,
                    query: str,
                    level: Optional[str],
                    start_time: Optional[datetime],
                    end_time: Optional[datetime],
                    limit: int) -> List[LogEntry]:
        """単一ファイル検索"""
        results = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_no, line in enumerate(f, 1):
                    if len(results) >= limit:
                        break

                    entry = self._parse_log_line(line.strip(), str(file_path), line_no)
                    if not entry:
                        continue

                    # フィルタ適用
                    if not self._matches_filters(entry, query, level, start_time, end_time):
                        continue

                    results.append(entry)

        except Exception as e:
            logger.error(f"Error reading log file {file_path}: {e}")

        return results

    def _parse_log_line(self, line: str, file_path: str, line_no: int) -> Optional[LogEntry]:
        """ログ行解析"""
        if not line:
            return None

        # JSON形式の構造化ログを試す
        if line.startswith('{'):
            try:
                data = json.loads(line)
                return LogEntry(
                    timestamp=data.get('timestamp', ''),
                    level=data.get('level', ''),
                    logger=data.get('logger', ''),
                    message=data.get('message', ''),
                    file_path=file_path,
                    line_number=line_no
                )
            except json.JSONDecodeError:
                pass

        # 標準フォーマット解析: YYYY-MM-DD HH:MM:SS - logger - LEVEL - message
        patterns = [
            r'(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}) - ([^-]+) - (\\w+) - (.+)',
            r'(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d+) (\\w+) ([^:]+): (.+)',
            r'\\[(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2})\\] (\\w+) ([^:]+): (.+)'
        ]

        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                groups = match.groups()
                return LogEntry(
                    timestamp=groups[0],
                    level=groups[1] if len(groups) > 2 else 'INFO',
                    logger=groups[2] if len(groups) > 3 else 'unknown',
                    message=groups[3] if len(groups) > 3 else groups[1],
                    file_path=file_path,
                    line_number=line_no
                )

        # フォールバック: 全体をメッセージとして扱う
        return LogEntry(
            timestamp=datetime.now().isoformat(),
            level='INFO',
            logger='unknown',
            message=line,
            file_path=file_path,
            line_number=line_no
        )

    def _matches_filters(self,
                        entry: LogEntry,
                        query: str,
                        level: Optional[str],
                        start_time: Optional[datetime],
                        end_time: Optional[datetime]) -> bool:
        """フィルタマッチング"""

        # レベルフィルタ
        if level and entry.level.upper() != level.upper():
            return False

        # クエリフィルタ
        if query:
            query_lower = query.lower()
            if not (query_lower in entry.message.lower() or
                   query_lower in entry.logger.lower()):
                return False

        # 時間フィルタ
        if start_time or end_time:
            try:
                # タイムスタンプ解析
                entry_time = self._parse_timestamp(entry.timestamp)
                if start_time and entry_time < start_time:
                    return False
                if end_time and entry_time > end_time:
                    return False
            except Exception:
                # タイムスタンプ解析失敗時はスキップ
                pass

        return True

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """タイムスタンプ解析"""
        # ISO形式
        try:
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            pass

        # 一般的なフォーマット
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S,%f',
            '%Y-%m-%d %H:%M:%S.%f',
            '%d/%b/%Y %H:%M:%S'
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue

        # フォールバック
        return datetime.now()

    def get_log_stats(self) -> Dict[str, Any]:
        """ログ統計取得"""
        if not self.log_dir.exists():
            return {'error': 'Log directory not found'}

        stats = {
            'total_files': 0,
            'total_size': 0,
            'level_counts': {level: 0 for level in self.log_levels},
            'recent_errors': []
        }

        log_files = list(self.log_dir.glob("*.log"))
        log_files.extend(self.log_dir.glob("*.log.*"))

        for log_file in log_files:
            stats['total_files'] += 1
            stats['total_size'] += log_file.stat().st_size

            # 最近のエラーを取得
            try:
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    # ファイル末尾から読み取り
                    lines = f.readlines()
                    for line in lines[-100:]:  # 最後の100行
                        if 'ERROR' in line or 'CRITICAL' in line:
                            stats['recent_errors'].append(line.strip())
                            if len(stats['recent_errors']) >= 10:
                                break
            except Exception:
                pass

        return stats

    def tail_logs(self, lines: int = 50, follow: bool = False) -> Iterator[str]:
        """ログテール"""
        log_files = list(self.log_dir.glob("*.log"))
        if not log_files:
            return

        # 最新のログファイル
        latest_file = max(log_files, key=lambda x: x.stat().st_mtime)

        try:
            with open(latest_file, 'r', encoding='utf-8', errors='ignore') as f:
                # 末尾から指定行数読み取り
                all_lines = f.readlines()
                for line in all_lines[-lines:]:
                    yield line.rstrip()

                if follow:
                    # ファイル変更監視（簡易版）
                    last_size = latest_file.stat().st_size
                    f.seek(0, 2)  # ファイル末尾へ

                    while True:
                        current_size = latest_file.stat().st_size
                        if current_size > last_size:
                            new_data = f.read()
                            for line in new_data.splitlines():
                                yield line.rstrip()
                            last_size = current_size
                        time.sleep(1)

        except Exception as e:
            logger.error(f"Error tailing log file: {e}")


# Global instance
_log_searcher = None

def get_log_searcher() -> LogSearcher:
    """Get global log searcher instance"""
    global _log_searcher
    if _log_searcher is None:
        _log_searcher = LogSearcher()
    return _log_searcher