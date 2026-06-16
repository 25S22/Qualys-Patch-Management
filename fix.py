# ─────────────────────────── MAIN ───────────────────────────
def main():
    session = build_session()
    try:
        terminated_instances = get_terminated_instance_dicts(
            FILEPATH,
            id_column="Resource ID",
            status_column="State"
        )
        found_ids = [item["Resource ID"] for item in terminated_instances]

        if not found_ids:
            log.info("No terminated instances found in input files")
            return

        login(session)

        hosts = fetch_all_hosts(session, max_workers=MAX_WORKERS)
        if not hosts:
            log.info("No assets found in Qualys")
            return

        df = build_dataframe(hosts)
        matched_df = match_terminated_instances(df, found_ids)

        if matched_df.empty:
            log.info("No matching assets found in Qualys — nothing to purge")
            return

        export_matched_excel(matched_df)

        # ── PURGE ──────────────────────────────────────────────────────────
        qualys_ids = matched_df["Qualys ID"].astype(str).str.strip().tolist()
        qualys_ids = [i for i in qualys_ids if i]          # drop blanks

        if not qualys_ids:
            log.warning("Matched rows found but no valid Qualys IDs — skipping purge")
            return

        print(f"\n{'='*60}")
        print(f"  Starting purge of {len(qualys_ids)} matched asset(s)...")
        print(f"{'='*60}")

        deleted_ids = purge_assets(session, qualys_ids)

        print(f"\n{'='*60}")
        if deleted_ids:
            print(f"  ✅  Purge complete — {len(deleted_ids)}/{len(qualys_ids)} asset(s) deleted:")
            for aid in deleted_ids:
                print(f"      • Asset ID {aid}")
        else:
            print("  ⚠️   Purge ran but no assets were confirmed deleted.")
            print("      Check Qualys permissions or API response codes.")

        failed = set(qualys_ids) - set(deleted_ids)
        if failed:
            print(f"\n  ❌  {len(failed)} asset(s) were NOT deleted:")
            for aid in sorted(failed):
                print(f"      • Asset ID {aid}")

        print(f"{'='*60}\n")

    finally:
        logout(session)
