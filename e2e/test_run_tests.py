#!/usr/bin/env python3

"""Tests for the RunCommand with test."""

import os
import sys
import unittest

from codemcp.testing import MCPEndToEndTestCase


class RunCommandTestTest(MCPEndToEndTestCase):
    """Test the RunCommand with test subtool."""

    async def test_run_tests_with_run_subtool(self):
        """Test the RunCommand with test command."""
        # Create a test directory for testing
        test_dir = os.path.join(self.temp_dir.name, "test_directory")
        os.makedirs(test_dir, exist_ok=True)

        # Create a test.py file with a simple test
        test_file_path = os.path.join(test_dir, "test_simple.py")
        with open(test_file_path, "w") as f:
            f.write("""
import unittest

class SimpleTestCase(unittest.TestCase):
    def test_success(self):
        self.assertEqual(1 + 1, 2)

    def test_another_success(self):
        self.assertTrue(True)
""")

        # Create a second test file with another test
        test_file_path2 = os.path.join(test_dir, "test_another.py")
        with open(test_file_path2, "w") as f:
            f.write("""
import unittest

class AnotherTestCase(unittest.TestCase):
    def test_success(self):
        self.assertEqual(2 + 2, 4)
""")

        # Create a run_test.sh script to mimic the real one
        # Get the current Python executable path
        current_python = os.path.abspath(sys.executable)

        # Create run_test.sh script using the current Python executable
        runner_script_path = os.path.join(self.temp_dir.name, "run_test.sh")
        with open(runner_script_path, "w") as f:
            f.write(f"""#!/bin/bash
set -e
cd "$(dirname "$0")"
{current_python} -m pytest $@
""")
        os.chmod(runner_script_path, 0o755)  # Make it executable

        # Update codemcp.toml to include the test subtool
        config_path = os.path.join(self.temp_dir.name, "codemcp.toml")
        with open(config_path, "w") as f:
            f.write("""
[project]
name = "test-project"

[commands]
test = ["./run_test.sh"]
""")

        # Add files to git
        await self.git_run(["add", "."])
        await self.git_run(["commit", "-m", "Add test files"])

        async with self.create_client_session() as session:
            # First initialize project to get chat_id
            init_result_text = await self.call_tool_assert_success(
                session,
                "codemcp",
                {
                    "subtool": "InitProject",
                    "path": self.temp_dir.name,
                    "user_prompt": "Test initialization for run tests test",
                    "subject_line": "test: initialize for run tests test",
                    "reuse_head_chat_id": False,
                },
            )

            # Extract chat_id from the init result
            chat_id = self.extract_chat_id_from_text(init_result_text)

            # Call the RunCommand tool with test command and chat_id
            result_text = await self.call_tool_assert_success(
                session,
                "codemcp",
                {
                    "subtool": "RunCommand",
                    "path": self.temp_dir.name,
                    "command": "test",
                    "chat_id": chat_id,
                },
            )

            # Verify the success message
            self.assertIn("Code test successful", result_text)

            # Call the RunCommand tool with test command and arguments
            selector_result_text = await self.call_tool_assert_success(
                session,
                "codemcp",
                {
                    "subtool": "RunCommand",
                    "path": self.temp_dir.name,
                    "command": "test",
                    "arguments": ["test_directory/test_another.py"],
                    "chat_id": chat_id,
                },
            )

            # Use the result text directly

            # Verify the success message
            self.assertIn("Code test successful", selector_result_text)
            # Verify that the selector was used
            self.assertIn("test_another.py", selector_result_text)
            self.assertNotIn("test_simple.py", selector_result_text)

    async def test_run_tests_with_string_arguments(self):
        """Test the RunCommand with string arguments that should be parsed."""
        # Create a test directory for testing
        test_dir = os.path.join(self.temp_dir.name, "test_directory")
        os.makedirs(test_dir, exist_ok=True)

        # Create a test.py file with a simple test
        test_file_path = os.path.join(test_dir, "test_simple.py")
        with open(test_file_path, "w") as f:
            f.write("""
import unittest

class SimpleTestCase(unittest.TestCase):
    def test_success(self):
        self.assertEqual(1 + 1, 2)

    def test_another_success(self):
        self.assertTrue(True)
""")

        # Create a second test file with another test
        test_file_path2 = os.path.join(test_dir, "test_another.py")
        with open(test_file_path2, "w") as f:
            f.write("""
import unittest

class AnotherTestCase(unittest.TestCase):
    def test_success(self):
        self.assertEqual(2 + 2, 4)
""")

        # Get the current Python executable path
        current_python = os.path.abspath(sys.executable)

        # Create run_test.sh script using the current Python executable
        runner_script_path = os.path.join(self.temp_dir.name, "run_test.sh")
        with open(runner_script_path, "w") as f:
            f.write(f"""#!/bin/bash
set -e
cd "$(dirname "$0")"
{current_python} -m pytest $@
""")
        os.chmod(runner_script_path, 0o755)  # Make it executable

        # Update codemcp.toml to include the test subtool
        config_path = os.path.join(self.temp_dir.name, "codemcp.toml")
        with open(config_path, "w") as f:
            f.write("""
[project]
name = "test-project"

[commands]
test = ["./run_test.sh"]
""")

        # Add files to git
        await self.git_run(["add", "."])
        await self.git_run(["commit", "-m", "Add test files"])

        async with self.create_client_session() as session:
            # First initialize project to get chat_id
            init_result_text = await self.call_tool_assert_success(
                session,
                "codemcp",
                {
                    "subtool": "InitProject",
                    "path": self.temp_dir.name,
                    "user_prompt": "Test initialization for string arguments test",
                    "subject_line": "test: initialize for string arguments test",
                    "reuse_head_chat_id": False,
                },
            )

            # Extract chat_id from the init result
            chat_id = self.extract_chat_id_from_text(init_result_text)

            # Test 1: Test with a string argument containing a specific test selector
            # This tests the basic space-separated argument parsing
            result_text = await self.call_tool_assert_success(
                session,
                "codemcp",
                {
                    "subtool": "RunCommand",
                    "path": self.temp_dir.name,
                    "command": "test",
                    "arguments": "test_directory/test_simple.py::SimpleTestCase::test_success",
                    "chat_id": chat_id,
                },
            )

            # Verify the success message and proper argument parsing
            self.assertIn("Code test successful", result_text)
            # We should see evidence that the test was run with the specific test case
            self.assertIn("test_simple.py", result_text)
            self.assertIn("1 passed", result_text)
            # Only one test should be run due to the specific selector
            self.assertIn("collected 1 item", result_text)

            # Test 2: Test with multiple arguments separated by spaces in a single string
            # This verifies that the string is split into multiple arguments
            multi_arg_test = await self.call_tool_assert_success(
                session,
                "codemcp",
                {
                    "subtool": "RunCommand",
                    "path": self.temp_dir.name,
                    "command": "test",
                    "arguments": "test_directory/test_simple.py -k test_success",
                    "chat_id": chat_id,
                },
            )

            # Verify multiple space-separated arguments were parsed correctly
            self.assertIn("Code test successful", multi_arg_test)
            # Only the specific test should be run due to the -k filter
            self.assertIn("collected 2 items", multi_arg_test)
            self.assertIn("1 passed, 1 deselected", multi_arg_test)


if __name__ == "__main__":
    unittest.main()
