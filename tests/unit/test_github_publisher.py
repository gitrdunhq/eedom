# tested-by: tests/unit/test_github_publisher.py
"""Contract tests for GitHubPublisher adapter (issue #177).

RED phase: all tests import from eedom.adapters.github_publisher which does not exist yet.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from eedom.adapters.github_publisher import (
    GitHubPublisher,  # noqa: F401 — will ImportError until green
)
from eedom.core.ports import PullRequestPublisherPort

# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


class TestProtocolConformance:
    def test_github_publisher_satisfies_pull_request_publisher_port(self):
        """GitHubPublisher must be an instance of PullRequestPublisherPort."""
        pub = GitHubPublisher()
        assert isinstance(pub, PullRequestPublisherPort)


# ---------------------------------------------------------------------------
# Constructor
# ---------------------------------------------------------------------------


class TestConstructor:
    def test_constructor_accepts_no_args(self):
        """Constructor works with no arguments (token defaults to None)."""
        pub = GitHubPublisher()
        assert pub.token is None

    def test_constructor_accepts_token(self):
        """Constructor accepts an explicit token string."""
        pub = GitHubPublisher(token="ghp_abc123")
        assert pub.token == "ghp_abc123"


# ---------------------------------------------------------------------------
# post_comment
# ---------------------------------------------------------------------------


class TestPostComment:
    def test_post_comment_returns_true_on_success(self):
        """post_comment returns True when gh CLI exits 0."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = pub.post_comment("org/repo", 42, "great work")
        assert result is True

    def test_post_comment_returns_false_on_failure(self):
        """post_comment returns False when gh CLI exits non-zero."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            result = pub.post_comment("org/repo", 42, "great work")
        assert result is False

    def test_post_comment_calls_gh_cli(self):
        """post_comment must invoke the `gh` CLI."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("org/repo", 7, "body text")
        args = mock_run.call_args[0][0]
        assert args[0] == "gh"

    def test_post_comment_passes_repo_and_pr_number(self):
        """gh CLI call must include the repo and PR number."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("myorg/myrepo", 99, "hello")
        args = mock_run.call_args[0][0]
        cmd_str = " ".join(str(a) for a in args)
        assert "myorg/myrepo" in cmd_str
        assert "99" in cmd_str

    def test_post_comment_passes_body(self):
        """gh CLI call must include the comment body."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("org/repo", 1, "unique-body-text")
        # Body might be passed as arg or via stdin — check call args list
        call_args = mock_run.call_args
        all_args = " ".join(str(a) for a in call_args[0][0])
        all_kwargs = str(call_args[1]) if call_args[1] else ""
        assert "unique-body-text" in all_args or "unique-body-text" in all_kwargs

    def test_post_comment_sets_token_env_when_provided(self):
        """When token is set, GH_TOKEN must be in the subprocess env."""
        pub = GitHubPublisher(token="ghp_secret")
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_comment("org/repo", 1, "body")
        kwargs = mock_run.call_args[1]
        env = kwargs.get("env") or {}
        assert env.get("GH_TOKEN") == "ghp_secret"

    def test_post_comment_returns_false_on_exception(self):
        """post_comment returns False (does not raise) when subprocess raises."""
        pub = GitHubPublisher()
        with patch("subprocess.run", side_effect=FileNotFoundError("gh not found")):
            result = pub.post_comment("org/repo", 1, "body")
        assert result is False


# ---------------------------------------------------------------------------
# post_review
# ---------------------------------------------------------------------------


class TestPostReview:
    def test_post_review_returns_true_on_success(self):
        """post_review returns True when gh CLI exits 0."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = pub.post_review("org/repo", 5, {"event": "APPROVE", "body": "lgtm"})
        assert result is True

    def test_post_review_returns_false_on_failure(self):
        """post_review returns False when gh CLI exits non-zero."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            result = pub.post_review("org/repo", 5, {"event": "REQUEST_CHANGES"})
        assert result is False

    def test_post_review_calls_gh_cli(self):
        """post_review must invoke the `gh` CLI."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.post_review("org/repo", 3, {"event": "COMMENT"})
        args = mock_run.call_args[0][0]
        assert args[0] == "gh"

    def test_post_review_returns_false_on_exception(self):
        """post_review returns False (does not raise) when subprocess raises."""
        pub = GitHubPublisher()
        with patch("subprocess.run", side_effect=FileNotFoundError("gh not found")):
            result = pub.post_review("org/repo", 1, {})
        assert result is False


# ---------------------------------------------------------------------------
# add_label
# ---------------------------------------------------------------------------


class TestAddLabel:
    def test_add_label_returns_true_on_success(self):
        """add_label returns True when gh CLI exits 0."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            result = pub.add_label("org/repo", 12, "security")
        assert result is True

    def test_add_label_returns_false_on_failure(self):
        """add_label returns False when gh CLI exits non-zero."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="error")
            result = pub.add_label("org/repo", 12, "security")
        assert result is False

    def test_add_label_calls_gh_cli(self):
        """add_label must invoke the `gh` CLI."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.add_label("org/repo", 8, "needs-review")
        args = mock_run.call_args[0][0]
        assert args[0] == "gh"

    def test_add_label_passes_label_name(self):
        """gh CLI call must include the label name."""
        pub = GitHubPublisher()
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            pub.add_label("org/repo", 8, "my-special-label")
        args = mock_run.call_args[0][0]
        cmd_str = " ".join(str(a) for a in args)
        assert "my-special-label" in cmd_str

    def test_add_label_returns_false_on_exception(self):
        """add_label returns False (does not raise) when subprocess raises."""
        pub = GitHubPublisher()
        with patch("subprocess.run", side_effect=FileNotFoundError("gh not found")):
            result = pub.add_label("org/repo", 1, "label")
        assert result is False
