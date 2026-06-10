"""
test_functions.py
─────────────────
Test each function in qualys_purge.py independently WITHOUT needing
a real Qualys account. Uses mock HTTP responses where needed.

Run:
    pip install requests pandas openpyxl
    python test_functions.py
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import xml.etree.ElementTree as ET
import pandas as pd

# ── Make sure we can import the main module ──────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from qualys_purge import (
    build_verify_request,
    build_delete_request,
    build_request,
    flatten_element,
    build_dataframe,
    match_dead_instances,
    get_dead_instance_dicts,
    verify_assets,
    purge_batch,
    EC2_RAW_COL,
)

SEP = "─" * 60


# ─────────────────────────────────────────────────────────────────────────────
# 1. build_verify_request
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildVerifyRequest(unittest.TestCase):
    def test_ids_appear_in_xml(self):
        ids = ["101", "202", "303"]
        xml_bytes = build_verify_request(ids)
        text = xml_bytes.decode("utf-8") if isinstance(xml_bytes, bytes) else xml_bytes
        self.assertIn("101,202,303", text.replace(" ", "").replace("\n", ""))
        self.assertIn("ServiceRequest", text)
        print("  ✅ build_verify_request — IDs encoded correctly")

    def test_single_id(self):
        xml_bytes = build_verify_request(["999"])
        text = xml_bytes.decode("utf-8") if isinstance(xml_bytes, bytes) else xml_bytes
        self.assertIn("999", text)
        print("  ✅ build_verify_request — single ID works")


# ─────────────────────────────────────────────────────────────────────────────
# 2. build_delete_request
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildDeleteRequest(unittest.TestCase):
    def test_delete_xml_structure(self):
        ids = ["10", "20"]
        xml_bytes = build_delete_request(ids)
        text = xml_bytes.decode("utf-8") if isinstance(xml_bytes, bytes) else xml_bytes
        self.assertIn("10,20", text.replace(" ", "").replace("\n", ""))
        print("  ✅ build_delete_request — structure correct")


# ─────────────────────────────────────────────────────────────────────────────
# 3. build_request (pagination)
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildRequest(unittest.TestCase):
    def test_offset_and_page_size(self):
        xml_bytes = build_request(offset=201)
        root = ET.fromstring(xml_bytes)
        offset_val = root.findtext(".//startFromOffset")
        limit_val  = root.findtext(".//limitResults")
        self.assertEqual(offset_val, "201")
        self.assertIsNotNone(limit_val)
        print(f"  ✅ build_request — offset=201, limitResults={limit_val}")


# ─────────────────────────────────────────────────────────────────────────────
# 4. flatten_element
# ─────────────────────────────────────────────────────────────────────────────
class TestFlattenElement(unittest.TestCase):
    def _make_host_xml(self):
        return ET.fromstring("""
        <HostAsset>
          <id>12345</id>
          <address>10.0.0.1</address>
          <dnsHostName>web-server-01</dnsHostName>
          <sourceInfo>
            <list>
              <Ec2AssetSourceSimple>
                <instanceId>i-0abc123456789</instanceId>
              </Ec2AssetSourceSimple>
            </list>
          </sourceInfo>
        </HostAsset>
        """)

    def test_flat_fields(self):
        host = self._make_host_xml()
        flat = flatten_element(host)
        self.assertEqual(flat.get("id"), "12345")
        self.assertEqual(flat.get("address"), "10.0.0.1")
        print("  ✅ flatten_element — top-level fields extracted")

    def test_nested_ec2_id(self):
        host = self._make_host_xml()
        flat = flatten_element(host)
        # Check the nested instanceId path
        nested_key = "sourceInfo.list.Ec2AssetSourceSimple.instanceId"
        self.assertIn(nested_key, flat)
        self.assertEqual(flat[nested_key], "i-0abc123456789")
        print(f"  ✅ flatten_element — nested EC2 ID found at '{nested_key}'")


# ─────────────────────────────────────────────────────────────────────────────
# 5. build_dataframe
# ─────────────────────────────────────────────────────────────────────────────
class TestBuildDataframe(unittest.TestCase):
    def _hosts(self):
        xml = """<HostAsset>
          <id>{id}</id>
          <address>{ip}</address>
          <sourceInfo><list><Ec2AssetSourceSimple>
            <instanceId>{ec2}</instanceId>
          </Ec2AssetSourceSimple></list></sourceInfo>
        </HostAsset>"""
        hosts = [
            ET.fromstring(xml.format(id="1", ip="10.0.0.1", ec2="i-0aaa")),
            ET.fromstring(xml.format(id="2", ip="10.0.0.2", ec2="i-0bbb")),
        ]
        return hosts

    def test_dataframe_shape(self):
        df = build_dataframe(self._hosts())
        self.assertEqual(len(df), 2)
        self.assertIn("EC2 Instance ID", df.columns)
        self.assertIn("id", df.columns)
        print(f"  ✅ build_dataframe — {len(df)} rows, columns: {list(df.columns)}")

    def test_ec2_instance_id_column(self):
        df = build_dataframe(self._hosts())
        self.assertListEqual(df["EC2 Instance ID"].tolist(), ["i-0aaa", "i-0bbb"])
        print("  ✅ build_dataframe — EC2 Instance ID column populated correctly")


# ─────────────────────────────────────────────────────────────────────────────
# 6. match_dead_instances
# ─────────────────────────────────────────────────────────────────────────────
class TestMatchDeadInstances(unittest.TestCase):
    def _make_df(self):
        return pd.DataFrame({
            "id":       ["101", "102", "103", "104"],
            "address":  ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
            EC2_RAW_COL: ["i-0aaa", "i-0bbb", "i-0ccc", "i-0ddd"],
        })

    def test_matches_correctly(self):
        df = self._make_df()
        # i-0bbb and i-0ddd are "dead"
        matched = match_dead_instances(df, ["i-0bbb", "i-0ddd"])
        self.assertEqual(len(matched), 2)
        self.assertIn("i-0bbb", matched["EC2 Instance ID"].values)
        self.assertIn("i-0ddd", matched["EC2 Instance ID"].values)
        print(f"  ✅ match_dead_instances — found {len(matched)} matches (expected 2)")

    def test_no_match(self):
        df = self._make_df()
        matched = match_dead_instances(df, ["i-0zzz"])
        self.assertEqual(len(matched), 0)
        print("  ✅ match_dead_instances — returns empty DataFrame when no match")

    def test_missing_ec2_column(self):
        df = pd.DataFrame({"id": ["1"], "address": ["10.0.0.1"]})
        matched = match_dead_instances(df, ["i-0aaa"])
        self.assertEqual(len(matched), 0)
        print("  ✅ match_dead_instances — handles missing EC2 column gracefully")


# ─────────────────────────────────────────────────────────────────────────────
# 7. get_dead_instance_dicts  (reads from actual test files)
# ─────────────────────────────────────────────────────────────────────────────
class TestGetDeadInstanceDicts(unittest.TestCase):
    TEST_DIR = "./test_data"

    def test_reads_files_and_filters(self):
        if not os.path.isdir(self.TEST_DIR):
            self.skipTest("Run create_test_data.py first to generate test files")

        result = get_dead_instance_dicts(self.TEST_DIR, id_column="Resource ID", status_column="State")
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

        # All returned entries should be stopped or terminated
        for item in result:
            state = item.get("State", "").lower()
            self.assertRegex(state, r"stopped|terminated",
                             msg=f"Unexpected state: {state}")

        print(f"  ✅ get_dead_instance_dicts — returned {len(result)} dead instances")
        for item in result:
            print(f"     → {item['Resource ID']}  [{item['State']}]")

    def test_empty_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            result = get_dead_instance_dicts(tmpdir)
            self.assertEqual(result, [])
        print("  ✅ get_dead_instance_dicts — returns [] for empty directory")


# ─────────────────────────────────────────────────────────────────────────────
# 8. verify_assets  (mocked HTTP)
# ─────────────────────────────────────────────────────────────────────────────
MOCK_VERIFY_XML = b"""<?xml version="1.0"?>
<ServiceResponse>
  <data>
    <HostAsset>
      <id>101</id>
      <address>10.0.0.1</address>
      <dnsHostName>host-a</dnsHostName>
    </HostAsset>
    <HostAsset>
      <id>102</id>
      <address>10.0.0.2</address>
      <dnsHostName>host-b</dnsHostName>
    </HostAsset>
  </data>
</ServiceResponse>"""

class TestVerifyAssets(unittest.TestCase):
    @patch("qualys_purge.generate_session")
    def test_returns_dict_of_assets(self, mock_gen):
        mock_response = MagicMock()
        mock_response.content = MOCK_VERIFY_XML
        mock_gen.return_value = mock_response

        session = MagicMock()
        result = verify_assets(session, ["101", "102", "999"])

        self.assertIn("101", result)
        self.assertIn("102", result)
        self.assertTrue(result["101"]["found"])
        self.assertEqual(result["102"]["hostname"], "host-b")
        # 999 not in XML, so not in results
        self.assertNotIn("999", result)
        print(f"  ✅ verify_assets — found {len(result)} assets (101, 102); 999 not matched as expected")


# ─────────────────────────────────────────────────────────────────────────────
# 9. purge_batch  (mocked HTTP)
# ─────────────────────────────────────────────────────────────────────────────
MOCK_PURGE_SUCCESS = b"""<?xml version="1.0"?>
<ServiceResponse>
  <responseCode>SUCCESS</responseCode>
</ServiceResponse>"""

MOCK_PURGE_FAIL = b"""<?xml version="1.0"?>
<ServiceResponse>
  <responseCode>FAILED</responseCode>
  <responseErrorDetails><errorMessage>Not found</errorMessage></responseErrorDetails>
</ServiceResponse>"""

class TestPurgeBatch(unittest.TestCase):
    @patch("qualys_purge.generate_session")
    def test_success_returns_ids(self, mock_gen):
        mock_gen.return_value.content = MOCK_PURGE_SUCCESS
        result = purge_batch(MagicMock(), ["101", "102"])
        self.assertEqual(result, ["101", "102"])
        print("  ✅ purge_batch — SUCCESS returns all IDs")

    @patch("qualys_purge.generate_session")
    def test_failure_returns_empty(self, mock_gen):
        mock_gen.return_value.content = MOCK_PURGE_FAIL
        result = purge_batch(MagicMock(), ["101"])
        self.assertEqual(result, [])
        print("  ✅ purge_batch — FAILED returns empty list")


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────
def run_tests():
    suites = [
        ("build_verify_request",    TestBuildVerifyRequest),
        ("build_delete_request",    TestBuildDeleteRequest),
        ("build_request",           TestBuildRequest),
        ("flatten_element",         TestFlattenElement),
        ("build_dataframe",         TestBuildDataframe),
        ("match_dead_instances",    TestMatchDeadInstances),
        ("get_dead_instance_dicts", TestGetDeadInstanceDicts),
        ("verify_assets (mocked)",  TestVerifyAssets),
        ("purge_batch (mocked)",    TestPurgeBatch),
    ]

    total_pass = total_fail = 0
    for name, cls in suites:
        print(f"\n{SEP}")
        print(f"  TEST: {name}")
        print(SEP)
        loader = unittest.TestLoader()
        suite  = loader.loadTestsFromTestCase(cls)
        # Flatten the suite so we can iterate individual tests
        tests = list(suite)
        for test in tests:
            try:
                test.debug()
                total_pass += 1
            except unittest.SkipTest as skip:
                print(f"  ⏭  {test._testMethodName} SKIPPED: {skip}")
            except Exception as e:
                print(f"  ❌ {test._testMethodName} FAILED: {e}")
                total_fail += 1

    print(f"\n{'=' * 60}")
    print(f"  RESULTS: {total_pass} passed  |  {total_fail} failed")
    print(f"{'=' * 60}\n")


if __name__ == "__main__":
    run_tests()
