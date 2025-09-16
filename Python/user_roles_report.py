import os
import sqlite3
from pathlib import Path
import zstandard
import csv


def resolve_table_name(conn, base_name):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ? ORDER BY name DESC LIMIT 1", (f"v%_{base_name}",))
    row = cur.fetchone()
    if row and row[0]:
        return row[0]
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name = ?", (base_name,))
    row = cur.fetchone()
    return row[0] if row else None


def get_latest_finished_sync_id(conn):
    cur = conn.cursor()
    sync_runs_table = resolve_table_name(conn, "sync_runs")
    if not sync_runs_table:
        return None
    cur.execute(
        f"SELECT sync_id FROM {sync_runs_table} WHERE ended_at IS NOT NULL ORDER BY ended_at DESC LIMIT 1"
    )
    row = cur.fetchone()
    return row[0] if row else None


def decompress_c1z(c1z_path, output_path):
    with open(c1z_path, 'rb') as compressed:
        header = compressed.read(5)
        if header != b"C1ZF\x00":
            raise ValueError("Invalid C1Z header; expected b'C1ZF\\x00'")
        dctx = zstandard.ZstdDecompressor()
        with open(output_path, 'wb') as decompressed:
            with dctx.stream_reader(compressed) as reader:
                while True:
                    chunk = reader.read(1 << 16)
                    if not chunk:
                        break
                    decompressed.write(chunk)


def find_c1z_path():
    # Prefer local directory first
    local = Path.cwd() / "sync.c1z"
    if local.exists():
        return str(local)
    # Fall back to repo baton-sql directory
    repo_root = Path(__file__).resolve().parent.parent
    alt = repo_root / "baton-sql" / "sync.c1z"
    if alt.exists():
        return str(alt)
    return None


def load_sqlite_path_from_c1z(c1z_path):
    # Try as direct SQLite first
    try:
        conn = sqlite3.connect(c1z_path)
        conn.execute("SELECT 1")
        conn.close()
        return c1z_path
    except Exception:
        pass

    # Decompress C1Z -> temp db
    tmp_db = Path(__file__).resolve().parent / "user_roles_tmp.db"
    if tmp_db.exists():
        try:
            tmp_db.unlink()
        except Exception:
            pass
    decompress_c1z(c1z_path, str(tmp_db))
    return str(tmp_db)


def main():
    c1z_path = find_c1z_path()
    if not c1z_path:
        print("Error: sync.c1z not found in current or baton-sql directory")
        return

    try:
        db_path = load_sqlite_path_from_c1z(c1z_path)
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        grants_table = resolve_table_name(conn, "grants")
        if not grants_table:
            raise ValueError("grants table not found in c1z")

        latest_sync_id = get_latest_finished_sync_id(conn)
        if not latest_sync_id:
            raise ValueError("No finished sync found in c1z")

        # Get all usernames from resources for the latest sync (ensures users with no roles are included)
        resources_table = resolve_table_name(conn, "resources")
        cursor.execute(
            f"SELECT external_id FROM {resources_table} WHERE resource_type_id = 'user' AND sync_id = ?",
            (latest_sync_id,),
        )
        usernames = set()
        for (external_id,) in cursor.fetchall():
            if isinstance(external_id, str) and ":" in external_id:
                usernames.add(external_id.split(":", 1)[1])
            else:
                usernames.add(str(external_id))

        # Map roles per user from grants
        cursor.execute(
            f"""
            SELECT principal_resource_id AS username,
                   resource_id AS role_name
            FROM {grants_table}
            WHERE sync_id = ?
              AND principal_resource_type_id = 'user'
              AND resource_type_id = 'role'
            """,
            (latest_sync_id,),
        )
        user_to_roles = {}
        for username, role_name in cursor.fetchall():
            user_to_roles.setdefault(username, set()).add(role_name)

        conn.close()

        out_path = Path(__file__).resolve().parent / "user_roles.csv"
        with open(str(out_path), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "role"])
            for username in sorted(usernames):
                roles = sorted(user_to_roles.get(username, []))
                if roles:
                    for role_name in roles:
                        writer.writerow([username, role_name])
                else:
                    writer.writerow([username, ""]) 

        print(f"Saved user-role mappings to {out_path} (rows={len(rows)})")
    except Exception as e:
        print(f"Error generating user roles report: {e}")


if __name__ == "__main__":
    main()


