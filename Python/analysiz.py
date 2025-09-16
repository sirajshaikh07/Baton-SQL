import sqlite3
import os
from pathlib import Path
import zstandard
import csv

def resolve_table_name(conn, base_name):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ? ORDER BY name DESC LIMIT 1", (f"v%_{base_name}",))
    row = cur.fetchone()
    if row and row[0]:
        return row[0]
    # fallback if unversioned
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
    """Decompress .c1z file"""
    with open(c1z_path, 'rb') as compressed:
        # C1Z files begin with the magic header b"C1ZF\x00" then zstd stream
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
        # Validate SQLite magic
        with open(output_path, 'rb') as f:
            magic = f.read(16)
        if not magic.startswith(b"SQLite format 3\x00"):
            raise ValueError("Decompressed output is not a SQLite database (bad magic)")

def analyze_c1z(file_path):
    """Analyze decompressed .c1z file"""
    conn = sqlite3.connect(file_path)
    cursor = conn.cursor()
    
    resources_table = resolve_table_name(conn, "resources")
    entitlements_table = resolve_table_name(conn, "entitlements")
    grants_table = resolve_table_name(conn, "grants")
    latest_sync_id = get_latest_finished_sync_id(conn)

    if not all([resources_table, entitlements_table, grants_table]):
        raise ValueError(f"Expected tables not found. Got: resources={resources_table}, entitlements={entitlements_table}, grants={grants_table}")
    if not latest_sync_id:
        raise ValueError("No finished sync found in c1z (sync_runs empty or unfinished)")

    cursor.execute(f"SELECT COUNT(*) FROM {resources_table} WHERE sync_id = ?", (latest_sync_id,))
    resources = cursor.fetchone()[0]
    
    cursor.execute(f"SELECT COUNT(*) FROM {entitlements_table} WHERE sync_id = ?", (latest_sync_id,))
    entitlements = cursor.fetchone()[0]
    
    cursor.execute(f"SELECT COUNT(*) FROM {grants_table} WHERE sync_id = ?", (latest_sync_id,))
    grants = cursor.fetchone()[0]
    
    print("=" * 50)
    print(f"ANALYSIS OF: {file_path}")
    print("=" * 50)
    print(f"📊 Resources found: {resources}")
    print(f"🎯 Entitlements found: {entitlements}")
    print(f"🔑 Grants found: {grants}")
    
    cursor.execute(f"SELECT resource_type_id, COUNT(*) FROM {resources_table} WHERE sync_id = ? GROUP BY resource_type_id", (latest_sync_id,))
    resource_breakdown = cursor.fetchall()
    print("\n📈 Resource Types:")
    for rt, cnt in resource_breakdown:
        print(f"   - {rt}: {cnt}")
    
    conn.close()

    # Single spreadsheet-like CSV: username, roles, entitlements, grants
    try:
        conn = sqlite3.connect(file_path)
        cursor = conn.cursor()
        resources_table = resolve_table_name(conn, "resources")
        grants_table = resolve_table_name(conn, "grants")
        entitlements_table = resolve_table_name(conn, "entitlements")
        latest_sync_id = get_latest_finished_sync_id(conn)

        # Build usernames from grants (authoritative raw principal IDs)
        cursor.execute(
            f"""
            SELECT DISTINCT principal_resource_id
            FROM {grants_table}
            WHERE sync_id = ? AND principal_resource_type_id = 'user'
            """,
            (latest_sync_id,),
        )
        usernames_from_grants = {row[0] for row in cursor.fetchall()}

        # Also add usernames derived from resources.external_id (fallback)
        cursor.execute(
            f"SELECT external_id FROM {resources_table} WHERE resource_type_id = ? AND sync_id = ?",
            ("user", latest_sync_id),
        )
        usernames_from_resources = set()
        for (external_id,) in cursor.fetchall():
            if isinstance(external_id, str) and ":" in external_id:
                usernames_from_resources.add(external_id.split(":", 1)[1])
            else:
                usernames_from_resources.add(str(external_id))

        users = sorted(usernames_from_grants.union(usernames_from_resources))

        # Build roles per user from grants (role memberships)
        cursor.execute(
            f"""
            SELECT principal_resource_id AS username, resource_id AS role_name
            FROM {grants_table}
            WHERE sync_id = ?
              AND resource_type_id = 'role'
              AND principal_resource_type_id = 'user'
            """,
            (latest_sync_id,),
        )
        user_roles = {}
        for username, role_name in cursor.fetchall():
            user_roles.setdefault(username, set()).add(role_name)

        # Entitlement counts per user (distinct entitlement ids)
        cursor.execute(
            f"""
            SELECT principal_resource_id AS username, COUNT(DISTINCT entitlement_id) AS ent_count
            FROM {grants_table}
            WHERE sync_id = ? AND principal_resource_type_id = 'user'
            GROUP BY principal_resource_id
            """,
            (latest_sync_id,),
        )
        user_ent_count = {row[0]: row[1] for row in cursor.fetchall()}

        # Grant counts per user (total)
        cursor.execute(
            f"""
            SELECT principal_resource_id AS username, COUNT(*) AS grant_count
            FROM {grants_table}
            WHERE sync_id = ? AND principal_resource_type_id = 'user'
            GROUP BY principal_resource_id
            """,
            (latest_sync_id,),
        )
        user_grant_count = {row[0]: row[1] for row in cursor.fetchall()}

        conn.close()

        # Write single CSV next to this script
        output_path = Path(__file__).resolve().parent / "report.csv"
        with open(str(output_path), "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "roles", "entitlements", "grants"])
            for username in sorted(users):
                roles_list = sorted(list(user_roles.get(username, [])))
                roles_str = ", ".join(roles_list)
                ent_count = user_ent_count.get(username, 0)
                grant_count = user_grant_count.get(username, 0)
                writer.writerow([username, roles_str, ent_count, grant_count])
        print(f"Saved consolidated report to {output_path} (users={len(users)})")
    except Exception as e:
        try:
            # At least write an empty file with headers if something failed
            output_path = Path(__file__).resolve().parent / "report.csv"
            with open(str(output_path), "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["username", "roles", "entitlements", "grants"])
            print(f"Saved empty report (due to error) to {output_path}")
        except Exception as e2:
            print(f"Report generation error (write failed): {e}; secondary error: {e2}")
        else:
            print(f"Report generation error: {e}")

# Main execution
def main():
    c1z_file = "sync.c1z"
    db_file = "decompressed.db"
    
    if not os.path.exists(c1z_file):
        # Also look in the repo's baton-sql directory
        repo_root = Path(__file__).resolve().parent.parent
        alt_path = repo_root / "baton-sql" / "sync.c1z"
        if alt_path.exists():
            c1z_file = str(alt_path)
        else:
            print(f"Error: {c1z_file} not found!")
            print(f"Also checked: {alt_path}")
            return
    
    try:
        # Try opening the file directly as SQLite first; if it fails, we'll decompress
        try:
            analyze_c1z(c1z_file)
            return
        except Exception:
            # fall through to decompression
            pass

        # Fall back to zstd decompression, then analyze the decompressed DB
        if os.path.exists(db_file):
            try:
                os.remove(db_file)
            except Exception:
                pass
        print(f"Decompressing .c1z file from: {c1z_file}")
        decompress_c1z(c1z_file, db_file)
        print("Decompression complete! Analyzing...")
        analyze_c1z(db_file)
        
    except Exception as e:
        print(f"Error: {e}")
        print("You may need to install zstandard: pip install zstandard")

if __name__ == "__main__":
    main()