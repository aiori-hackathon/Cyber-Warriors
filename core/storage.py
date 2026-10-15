"""
Storage and Persistence module for Authorised Attack-Surface Inventory and Change Monitor.
Manages baseline inventory, snapshot persistence (JSON format), and SQLite audit logs.
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from core.models import InventorySnapshot, Alert


class StorageManager:
    def __init__(self, data_dir: Optional[Path] = None):
        if data_dir is None:
            data_dir = Path(__file__).resolve().parent.parent / "data"
        self.data_dir = Path(data_dir)
        self.snapshots_dir = self.data_dir / "snapshots"
        self.reports_dir = self.data_dir.parent / "reports"
        
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        self.baseline_file = self.data_dir / "baseline.json"
        self.latest_scan_file = self.data_dir / "latest_scan.json"
        self.db_file = self.data_dir / "asm_history.db"
        
        self._init_sqlite_db()

    def _init_sqlite_db(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Snapshots table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                domain_count INTEGER DEFAULT 0,
                host_count INTEGER DEFAULT 0,
                open_ports_count INTEGER DEFAULT 0,
                alert_count INTEGER DEFAULT 0
            )
        """)
        
        # Alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                snapshot_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                target TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                confidence TEXT,
                false_positive_risk TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (snapshot_id) REFERENCES snapshots (snapshot_id)
            )
        """)
        
        conn.commit()
        conn.close()

    def save_snapshot(self, snapshot: InventorySnapshot, is_baseline: bool = False) -> Path:
        """Saves a scan snapshot to disk and SQLite audit history."""
        snap_data = snapshot.to_dict()
        file_path = self.snapshots_dir / f"snapshot_{snapshot.snapshot_id}.json"
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(snap_data, f, indent=2)
            
        with open(self.latest_scan_file, "w", encoding="utf-8") as f:
            json.dump(snap_data, f, indent=2)
            
        if is_baseline:
            with open(self.baseline_file, "w", encoding="utf-8") as f:
                json.dump(snap_data, f, indent=2)

        # Log into SQLite
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        total_open_ports = sum(len(h.open_ports) for h in snapshot.hosts)
        
        cursor.execute("""
            INSERT OR REPLACE INTO snapshots (snapshot_id, timestamp, domain_count, host_count, open_ports_count, alert_count)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            snapshot.snapshot_id,
            snapshot.timestamp,
            len(snapshot.domains),
            len(snapshot.hosts),
            total_open_ports,
            snapshot.summary_stats.get("alert_count", 0)
        ))
        conn.commit()
        conn.close()
        
        return file_path

    def load_baseline(self) -> Optional[Dict[str, Any]]:
        """Loads baseline inventory from file if exists."""
        if not self.baseline_file.exists():
            return None
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def load_latest(self) -> Optional[Dict[str, Any]]:
        """Loads latest scan snapshot from file if exists."""
        if not self.latest_scan_file.exists():
            return None
        with open(self.latest_scan_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def list_snapshots(self) -> List[Dict[str, Any]]:
        """Returns list of all saved snapshots."""
        conn = sqlite3.connect(self.db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM snapshots ORDER BY timestamp DESC")
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows

    def record_alerts(self, snapshot_id: str, alerts: List[Alert]):
        """Persists alerts generated during change comparison."""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        for a in alerts:
            cursor.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, snapshot_id, category, severity, target,
                    title, description, confidence, false_positive_risk, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                a.alert_id,
                snapshot_id,
                a.category.value if hasattr(a.category, 'value') else str(a.category),
                a.severity.value if hasattr(a.severity, 'value') else str(a.severity),
                a.target,
                a.title,
                a.description,
                a.confidence.value if hasattr(a.confidence, 'value') else str(a.confidence),
                a.false_positive_risk,
                a.timestamp
            ))
        conn.commit()
        conn.close()
