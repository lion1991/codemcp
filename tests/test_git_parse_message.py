#!/usr/bin/env python3

import unittest

from expecttest import TestCase

from codemcp.git_parse_message import parse_message


class TestGitMessage(TestCase):
    def test_empty_message(self):
        subject, body, trailers = parse_message("")
        self.assertEqual(subject, "")
        self.assertEqual(body, "")
        self.assertEqual(trailers, "")

    def test_subject_only(self):
        subject, body, trailers = parse_message("Subject line")
        self.assertEqual(subject, "Subject line")
        self.assertEqual(body, "")
        self.assertEqual(trailers, "")

    def test_no_trailers(self):
        message = "Subject line\n\nThis is the body of the commit message.\nIt spans multiple lines."
        subject, body, trailers = parse_message(message)
        self.assertEqual(subject, "Subject line")
        # Update the expected text to match what the function returns
        self.assertExpectedInline(
            body,
            """\
This is the body of the commit message.
It spans multiple lines.""",
        )
        self.assertEqual(trailers, "")

    def test_simple_trailers(self):
        message = "Subject line\n\nThis is the body of the commit message.\n\nSigned-off-by: Alice <alice@example.com>\nReviewed-by: Bob <bob@example.com>"
        subject, body, trailers = parse_message(message)
        self.assertEqual(subject, "Subject line")
        self.assertEqual(body, "This is the body of the commit message.")
        self.assertExpectedInline(
            trailers,
            """\
Signed-off-by: Alice <alice@example.com>
Reviewed-by: Bob <bob@example.com>""",
        )

    def test_trailers_with_continuation(self):
        message = "Subject line\n\nThis is the body of the commit message.\n\nSigned-off-by: Alice <alice@example.com>\nCo-authored-by: Bob <bob@example.com>\n  Carol <carol@example.com>\n  Dave <dave@example.com>"
        subject, body, trailers = parse_message(message)
        self.assertEqual(subject, "Subject line")
        self.assertEqual(body, "This is the body of the commit message.")
        self.assertExpectedInline(
            trailers,
            """\
Signed-off-by: Alice <alice@example.com>
Co-authored-by: Bob <bob@example.com>
  Carol <carol@example.com>
  Dave <dave@example.com>""",
        )

    def test_mixed_trailers_non_trailers(self):
        message = "Subject line\n\nThis is the body of the commit message.\n\nThis is not a trailer line.\nSigned-off-by: Alice <alice@example.com>\nAlso not a trailer.\nReviewed-by: Bob <bob@example.com>"
        subject, body, trailers = parse_message(message)
        self.assertEqual(subject, "Subject line")
        self.assertEqual(body, "This is the body of the commit message.")
        self.assertExpectedInline(
            trailers,
            """\
This is not a trailer line.
Signed-off-by: Alice <alice@example.com>
Also not a trailer.
Reviewed-by: Bob <bob@example.com>""",
        )

    def test_not_enough_trailers(self):
        message = "Subject line\n\nThis is the body of the commit message.\n\nNot-a-trailer: This is not a proper trailer\nAlso not a trailer."
        subject, body, trailers = parse_message(message)
        self.assertEqual(subject, "Subject line")
        self.assertExpectedInline(
            body,
            """\
This is the body of the commit message.

Not-a-trailer: This is not a proper trailer
Also not a trailer.""",
        )
        self.assertEqual(trailers, "")

    def test_duplicate_trailers(self):
        message = "Subject line\n\nThis is the body of the commit message.\n\nSigned-off-by: Alice <alice@example.com>\nSigned-off-by: Bob <bob@example.com>"
        subject, body, trailers = parse_message(message)
        self.assertEqual(subject, "Subject line")
        self.assertEqual(body, "This is the body of the commit message.")
        self.assertExpectedInline(
            trailers,
            """\
Signed-off-by: Alice <alice@example.com>
Signed-off-by: Bob <bob@example.com>""",
        )

    def test_cherry_picked_trailer(self):
        message = "Subject line\n\nThis is the body of the commit message.\n\n(cherry picked from commit abcdef1234567890)"
        subject, body, trailers = parse_message(message)
        self.assertEqual(subject, "Subject line")
        self.assertEqual(body, "This is the body of the commit message.")
        self.assertEqual(trailers, "(cherry picked from commit abcdef1234567890)")


if __name__ == "__main__":
    unittest.main()
