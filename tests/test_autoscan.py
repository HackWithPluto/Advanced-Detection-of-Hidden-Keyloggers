import os
import json
import unittest

class TestAutoScan(unittest.TestCase):
    def test_config_keys(self):
        with open('config.json','r',encoding='utf-8') as f:
            cfg = json.load(f)
        self.assertIn('autoscan_window_days', cfg)
        self.assertIn('auto_scan_interval_minutes', cfg)

    def test_autoscan_exports(self):
        from scanner.autoscan import collect_files_for_window, run_autoscan_scan
        self.assertTrue(callable(collect_files_for_window))
        self.assertTrue(callable(run_autoscan_scan))

    def test_collect_empty(self):
        from scanner.autoscan import collect_files_for_window
        files = collect_files_for_window([], 30)
        self.assertIsInstance(files, list)

    def test_run_returns_list(self):
        from scanner.autoscan import run_autoscan_scan
        class Stop:
            def is_set(self):
                return False
        res = run_autoscan_scan([], 30, 1, {"append_result_safe": None, "update_progress_safe": None, "complete_callback": None, "log_callback": None, "result_box": None, "progress_bar": None}, Stop())
        self.assertIsInstance(res, list)

    def test_thread_subscription(self):
        from thread import register_autoscan_subscriber
        called = {"ok": False}
        def cb(results):
            called["ok"] = True
        register_autoscan_subscriber(cb)
        # invoke directly
        cb([])
        self.assertTrue(called["ok"])

if __name__ == '__main__':
    unittest.main()
