#!/usr/bin/env python3
# Copyright 2026 The Inspektor Gadget authors
# Licensed under the Apache License, Version 2.0 (the "License");

import importlib.util
import pathlib
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("generate_classperms.py")
SPEC = importlib.util.spec_from_file_location("generate_classperms", MODULE_PATH)
assert SPEC and SPEC.loader
GEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GEN)


class GeneratorTest(unittest.TestCase):
    def test_pinned_fixture_is_complete_and_bounded(self):
        source = pathlib.Path(__file__).with_name("testdata").joinpath("classmap.h").read_text()
        classes = GEN.parse(source)
        self.assertEqual(97, len(classes))
        table = dict(classes)
        self.assertEqual(
            ["map_create", "map_read", "map_write", "prog_load", "prog_run", "map_create_as", "prog_load_as"],
            table["bpf"],
        )
        self.assertTrue(all(1 <= len(perms) <= 32 for _, perms in classes))

    def test_rejects_unknown_initializer_token(self):
        source = '''
#define COMMON_X "one"
const struct security_class_mapping secclass_map[] = {
    { "demo", { COMMON_X, BROKEN_TOKEN, NULL } },
};
'''
        with self.assertRaisesRegex(ValueError, "unknown initializer"):
            GEN.parse(source)

    def test_rejects_duplicate_classes(self):
        source = '''
const struct security_class_mapping secclass_map[] = {
    { "demo", { "one", NULL } },
    { "demo", { "two", NULL } },
};
'''
        with self.assertRaisesRegex(ValueError, "duplicate class"):
            GEN.parse(source)

    def test_rejects_more_than_32_permissions(self):
        perms = ", ".join(f'"p{i}"' for i in range(33))
        source = f'''const struct security_class_mapping secclass_map[] = {{
            {{ "demo", {{ {perms}, NULL }} }},
        }};'''
        with self.assertRaisesRegex(ValueError, "count=33"):
            GEN.parse(source)


if __name__ == "__main__":
    unittest.main()
