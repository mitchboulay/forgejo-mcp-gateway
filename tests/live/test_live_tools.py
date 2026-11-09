"""Every tool, against a real Forgejo, through the gateway's real HTTP stack."""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import httpx2
import pytest
from mcp.client.session import ClientSession

from .conftest import LiveTarget, mcp_session

pytestmark = pytest.mark.live

EXPECTED_TOOLS = {
    "get_me",
    "search_repositories",
    "list_owner_repositories",
    "get_repository",
    "list_branches",
    "list_directory",
    "get_file",
    "list_commits",
    "get_commit",
    "compare",
    "search_issues",
    "list_issues",
    "get_issue",
    "list_pull_requests",
    "get_pull_request",
    "list_action_runs",
    "list_releases",
    "create_issue",
    "update_issue",
    "add_comment",
    "create_branch",
    "write_file",
    "create_pull_request",
    "review_pull_request",
    "merge_pull_request",
}


async def call(session: ClientSession, tool: str, /, **arguments: Any) -> dict[str, Any]:
    result = await session.call_tool(tool, arguments)
    text = " ".join(getattr(block, "text", "") for block in result.content)
    assert not result.is_error, f"{tool} failed: {text}"
    assert isinstance(result.structured_content, dict), f"{tool} returned no structured content"
    return result.structured_content


async def call_error(session: ClientSession, tool: str, /, **arguments: Any) -> str:
    result = await session.call_tool(tool, arguments)
    assert result.is_error, f"{tool} should have failed"
    return " ".join(getattr(block, "text", "") for block in result.content)


async def test_unauthenticated_request_is_challenged(live: LiveTarget) -> None:
    async with httpx2.AsyncClient(timeout=30) as http:
        response = await http.post(f"{live.gateway_url}/mcp", json={})
    assert response.status_code == 401
    assert response.headers["www-authenticate"].startswith("Bearer")


async def test_wrong_token_is_refused(live: LiveTarget) -> None:
    async with httpx2.AsyncClient(timeout=30, headers={"Authorization": "Bearer not-a-real-token"}) as http:
        response = await http.post(f"{live.gateway_url}/mcp", json={})
    assert response.status_code == 401


async def test_read_tools(live: LiveTarget) -> None:
    async with mcp_session(live.gateway_url, live.token) as session:
        tools = await session.list_tools()
        assert {tool.name for tool in tools.tools} == EXPECTED_TOOLS
        read_only = {t.name for t in tools.tools if t.annotations and t.annotations.read_only_hint}
        assert "get_file" in read_only
        assert "write_file" not in read_only

        me = await call(session, "get_me")
        assert me["login"] == live.owner

        found = await call(session, "search_repositories", query=live.repo)
        assert f"{live.owner}/{live.repo}" in {r["full_name"] for r in found["items"]}
        owned = await call(session, "list_owner_repositories", owner=live.owner)
        assert f"{live.owner}/{live.repo}" in {r["full_name"] for r in owned["items"]}

        repository = await call(session, "get_repository", owner=live.owner, repo=live.repo)
        default_branch = repository["default_branch"]
        branches = await call(session, "list_branches", owner=live.owner, repo=live.repo)
        assert default_branch in {b["name"] for b in branches["items"]}

        root = await call(session, "list_directory", owner=live.owner, repo=live.repo)
        assert "README.md" in {e["name"] for e in root["entries"]}
        readme = await call(session, "get_file", owner=live.owner, repo=live.repo, file="README.md")
        assert readme["encoding"] == "utf-8"
        assert readme["total_lines"] >= 1
        first = await call(
            session, "get_file", owner=live.owner, repo=live.repo, file="README.md", start_line=1, end_line=1
        )
        assert first["content"] == readme["content"].splitlines(keepends=True)[0]
        directory_error = await call_error(session, "get_file", owner=live.owner, repo=live.repo, file="docs/..")
        assert "not a valid path segment" in directory_error
        # Regression: dot segments must never reach Forgejo, where httpx would resolve them into
        # another endpoint (here /api/v1/user) and return its body as file content.
        escape = await call_error(session, "get_file", owner=live.owner, repo=live.repo, file="../../../../user")
        assert "not a valid path segment" in escape
        assert "not a valid" in await call_error(session, "get_repository", owner="..", repo=live.repo)

        commits = await call(session, "list_commits", owner=live.owner, repo=live.repo, limit=5)
        head_sha = commits["items"][0]["sha"]
        commit = await call(session, "get_commit", owner=live.owner, repo=live.repo, sha=head_sha)
        assert commit["sha"] == head_sha
        assert isinstance(commit["diff"], str)

        await call(session, "list_action_runs", owner=live.owner, repo=live.repo)
        await call(session, "list_releases", owner=live.owner, repo=live.repo)

        missing = await call_error(
            session, "get_repository", owner=live.owner, repo="does-not-exist-" + uuid.uuid4().hex
        )
        assert "404" in missing


async def test_branch_file_pull_request_merge(live: LiveTarget) -> None:
    stamp = f"{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    branch = f"live/{stamp}"
    file = f"live-tests/{stamp}.md"
    async with mcp_session(live.gateway_url, live.token) as session:
        repository = await call(session, "get_repository", owner=live.owner, repo=live.repo)
        base = repository["default_branch"]

        created_branch = await call(session, "create_branch", owner=live.owner, repo=live.repo, name=branch)
        assert created_branch["name"] == branch

        written = await call(
            session,
            "write_file",
            owner=live.owner,
            repo=live.repo,
            file=file,
            content=f"# Live test {stamp}\n\nfirst version\n",
            message=f"live test: add {file}",
            branch=branch,
        )
        first_sha = written["sha"]
        updated = await call(
            session,
            "write_file",
            owner=live.owner,
            repo=live.repo,
            file=file,
            content=f"# Live test {stamp}\n\nsecond version, ünïcode ✓\n",
            message=f"live test: update {file}",
            branch=branch,
            sha=first_sha,
        )
        assert updated["sha"] != first_sha
        stale = await call_error(
            session,
            "write_file",
            owner=live.owner,
            repo=live.repo,
            file=file,
            content="blind overwrite\n",
            message="must be refused",
            branch=branch,
            sha=first_sha,
        )
        assert "Forgejo returned" in stale

        read_back = await call(session, "get_file", owner=live.owner, repo=live.repo, file=file, ref=branch)
        assert "second version, ünïcode ✓" in read_back["content"]

        history = await call(session, "list_commits", owner=live.owner, repo=live.repo, ref=branch, file=file)
        assert len(history["items"]) == 2
        diff = await call(session, "compare", owner=live.owner, repo=live.repo, base=base, head=branch)
        assert diff["total_commits"] == 2
        assert file in {f["filename"] for f in diff["files"]}

        pull = await call(
            session,
            "create_pull_request",
            owner=live.owner,
            repo=live.repo,
            title=f"Live test {stamp}",
            head=branch,
            base=base,
            body="Opened by the forgejo-mcp-gateway live suite.",
        )
        number = pull["number"]
        detail = await call(
            session, "get_pull_request", owner=live.owner, repo=live.repo, number=number, include_diff=True
        )
        assert file in {f["filename"] for f in detail["files"]}
        assert "second version" in detail["diff"]

        await call(session, "add_comment", owner=live.owner, repo=live.repo, number=number, body="Live comment.")
        thread = await call(session, "get_issue", owner=live.owner, repo=live.repo, number=number)
        assert thread["is_pull_request"] is True
        assert "Live comment." in {c["body"] for c in thread["comment_thread"]}

        review = await call(
            session,
            "review_pull_request",
            owner=live.owner,
            repo=live.repo,
            number=number,
            event="COMMENT",
            body="Looks fine.",
        )
        assert review["id"]

        listed = await call(session, "list_pull_requests", owner=live.owner, repo=live.repo)
        assert number in {p["number"] for p in listed["items"]}

        wrong_head = await call_error(
            session,
            "merge_pull_request",
            owner=live.owner,
            repo=live.repo,
            number=number,
            method="squash",
            head_sha="0" * 40,
        )
        assert "Forgejo returned" in wrong_head
        merged = await call(
            session,
            "merge_pull_request",
            owner=live.owner,
            repo=live.repo,
            number=number,
            method="squash",
            head_sha=detail["head_sha"],
            delete_branch=True,
        )
        assert merged["merged"] is True


async def test_issue_lifecycle(live: LiveTarget) -> None:
    stamp = uuid.uuid4().hex[:8]
    async with mcp_session(live.gateway_url, live.token) as session:
        issue = await call(
            session,
            "create_issue",
            owner=live.owner,
            repo=live.repo,
            title=f"Live issue {stamp}",
            body="Body with **markdown**.",
        )
        number = issue["number"]
        assert issue["state"] == "open"

        listed = await call(session, "list_issues", owner=live.owner, repo=live.repo)
        assert number in {i["number"] for i in listed["items"]}
        # Keyword search goes through Forgejo's issue indexer, which catches up asynchronously.
        for _ in range(20):
            searched = await call(session, "search_issues", query=stamp, kind="issues")
            if number in {i["number"] for i in searched["items"]}:
                break
            await asyncio.sleep(0.5)
        else:
            pytest.fail("search_issues never found the new issue")

        assert "Nothing to change" in await call_error(
            session, "update_issue", owner=live.owner, repo=live.repo, number=number
        )
        closed = await call(
            session,
            "update_issue",
            owner=live.owner,
            repo=live.repo,
            number=number,
            state="closed",
            title=f"Done {stamp}",
        )
        assert closed["state"] == "closed"
        assert closed["title"] == f"Done {stamp}"
