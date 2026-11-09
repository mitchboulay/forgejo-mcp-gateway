"""The MCP tools. Each one acts as the caller, with the caller's Forgejo token.

There are no admin, delete or settings tools: the worst a stolen connection can
do is what these tools do, within the scopes of the token behind it.

List tools are paginated (``page`` from 1, ``limit`` up to Forgejo's maximum of
50) and say whether more pages exist. Objects are projected to the fields an
assistant needs; text bodies, file contents and diffs are returned whole.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import time
from collections.abc import Awaitable, Callable
from typing import Annotated, Any, Literal, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from pydantic import Field

from .auth import GatewayTokenVerifier, current_principal
from .forgejo import ForgejoClient, ForgejoError, ForgejoUnauthorized, Page, file_path, path
from .oauth import Principal

log = logging.getLogger(__name__)

T = TypeVar("T")

# Forgejo name characters. "." and ".." pass this and are refused by forgejo.path() for every segment.
_NAME = r"^[A-Za-z0-9_.-]+$"
Owner = Annotated[
    str, Field(min_length=1, max_length=100, pattern=_NAME, description="Owner: a user or organization name.")
]
Repo = Annotated[str, Field(min_length=1, max_length=100, pattern=_NAME, description="Repository name.")]
Number = Annotated[int, Field(ge=1, description="Issue or pull request number.")]
PageNo = Annotated[int, Field(ge=1, description="Page number, from 1.")]
Limit = Annotated[int, Field(ge=1, le=50, description="Items per page (1-50).")]
Ref = Annotated[
    str | None,
    Field(default=None, max_length=255, description="Branch, tag or commit SHA. Default branch when omitted."),
]
IssueState = Literal["open", "closed", "all"]

MERGE_ATTEMPTS = 5
MERGE_RETRY_SECONDS = 1.0

READ = ToolAnnotations(read_only_hint=True, open_world_hint=False)
ADD = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False)
CHANGE = ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False)


# ── Projections ───────────────────────────────────────────────────────────────


def _user(data: Any) -> str | None:
    return str(data["login"]) if isinstance(data, dict) and data.get("login") else None


def _repo(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "full_name": data.get("full_name"),
        "description": data.get("description") or "",
        "private": data.get("private"),
        "archived": data.get("archived"),
        "fork": data.get("fork"),
        "default_branch": data.get("default_branch"),
        "html_url": data.get("html_url"),
        "ssh_url": data.get("ssh_url"),
        "clone_url": data.get("clone_url"),
        "stars": data.get("stars_count"),
        "open_issues": data.get("open_issues_count"),
        "open_pull_requests": data.get("open_pr_counter"),
        "updated_at": data.get("updated_at"),
        "permissions": data.get("permissions"),
    }


def _labels(data: dict[str, Any]) -> list[str]:
    return [str(label.get("name")) for label in data.get("labels") or []]


def _issue(data: dict[str, Any], *, with_body: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "number": data.get("number"),
        "title": data.get("title"),
        "state": data.get("state"),
        "is_pull_request": data.get("pull_request") is not None,
        "repository": (data.get("repository") or {}).get("full_name"),
        "author": _user(data.get("user")),
        "assignees": [_user(a) for a in data.get("assignees") or []],
        "labels": _labels(data),
        "milestone": (data.get("milestone") or {}).get("title"),
        "comments": data.get("comments"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "closed_at": data.get("closed_at"),
        "html_url": data.get("html_url"),
    }
    if with_body:
        out["body"] = data.get("body") or ""
    return out


def _pull(data: dict[str, Any], *, with_body: bool) -> dict[str, Any]:
    out: dict[str, Any] = {
        "number": data.get("number"),
        "title": data.get("title"),
        "state": data.get("state"),
        "draft": data.get("draft"),
        "merged": data.get("merged"),
        "mergeable": data.get("mergeable"),
        "author": _user(data.get("user")),
        "head": (data.get("head") or {}).get("label"),
        "head_sha": (data.get("head") or {}).get("sha"),
        "base": (data.get("base") or {}).get("ref"),
        "labels": _labels(data),
        "requested_reviewers": [_user(r) for r in data.get("requested_reviewers") or []],
        "comments": data.get("comments"),
        "additions": data.get("additions"),
        "deletions": data.get("deletions"),
        "changed_files": data.get("changed_files"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "merged_at": data.get("merged_at"),
        "merged_by": _user(data.get("merged_by")),
        "html_url": data.get("html_url"),
    }
    if with_body:
        out["body"] = data.get("body") or ""
    return out


def _commit(data: dict[str, Any]) -> dict[str, Any]:
    commit = data.get("commit") or {}
    author = commit.get("author") or {}
    return {
        "sha": data.get("sha"),
        "message": commit.get("message"),
        "author": author.get("name"),
        "author_login": _user(data.get("author")),
        "date": author.get("date"),
        "parents": [p.get("sha") for p in data.get("parents") or []],
        "stats": data.get("stats"),
        "files": [{"filename": f.get("filename"), "status": f.get("status")} for f in data.get("files") or []] or None,
        "html_url": data.get("html_url"),
    }


def _comment(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id"),
        "author": _user(data.get("user")),
        "body": data.get("body") or "",
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "html_url": data.get("html_url"),
    }


def _run(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id"),
        "number": data.get("index_in_repo"),
        "title": data.get("title"),
        "workflow": data.get("workflow_id"),
        "status": data.get("status"),
        "event": data.get("trigger_event") or data.get("event"),
        "ref": data.get("prettyref"),
        "commit_sha": data.get("commit_sha"),
        "triggered_by": _user(data.get("trigger_user")),
        "created": data.get("created"),
        "started": data.get("started"),
        "stopped": data.get("stopped"),
        "html_url": data.get("html_url"),
    }


def _release(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": data.get("id"),
        "tag": data.get("tag_name"),
        "name": data.get("name"),
        "draft": data.get("draft"),
        "prerelease": data.get("prerelease"),
        "body": data.get("body") or "",
        "author": _user(data.get("author")),
        "published_at": data.get("published_at"),
        "assets": [
            {"name": a.get("name"), "size": a.get("size"), "download_url": a.get("browser_download_url")}
            for a in data.get("assets") or []
        ],
        "html_url": data.get("html_url"),
    }


def _page(result: Page, project: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
    return {
        "items": [project(item) for item in result.items],
        "page": result.page,
        "has_more": result.has_more,
        "total": result.total,
    }


def _decode_file(data: dict[str, Any]) -> tuple[str | None, str | None]:
    """(text, base64) for a file object from the contents API. Exactly one is set when content is present."""
    raw = data.get("content")
    if raw is None:
        return None, None
    try:
        blob = base64.b64decode(raw)
    except (binascii.Error, ValueError):
        return None, None
    try:
        return blob.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, base64.b64encode(blob).decode()


# ── Registration ──────────────────────────────────────────────────────────────


def register_tools(server: MCPServer, forgejo: ForgejoClient, verifier: GatewayTokenVerifier) -> None:
    async def act(tool: str, work: Callable[[str], Awaitable[T]]) -> T:
        """Run ``work`` with the caller's Forgejo token; log one line; turn failures into tool errors."""
        principal: Principal = current_principal()
        started = time.perf_counter()
        outcome = "ok"
        try:
            return await work(principal.forgejo_token)
        except ForgejoUnauthorized:
            outcome = "unauthorized"
            await verifier.forget(principal)
            raise ToolError(
                "Forgejo no longer accepts this connection's token. Reconnect, using a new Forgejo access token."
            ) from None
        except ForgejoError as exc:
            outcome = f"forgejo_{exc.status or 'unavailable'}"
            raise ToolError(str(exc)) from None
        except ToolError:
            outcome = "invalid"
            raise
        except Exception:
            outcome = "error"
            raise
        finally:
            log.info(
                "tool.call",
                extra={
                    "tool": tool,
                    "forgejo_login": principal.forgejo_login,
                    "auth": principal.kind,
                    "connection_id": principal.connection_id,
                    "outcome": outcome,
                    "latency_ms": round((time.perf_counter() - started) * 1000, 1),
                },
            )

    def repo_path(owner: str, repo: str, *rest: str | int) -> str:
        return path("repos", owner, repo, *rest)

    # ── Account and repositories ──────────────────────────────────────────────

    @server.tool(annotations=READ)
    async def get_me() -> dict[str, Any]:
        """Who this connection acts as on Forgejo, and the organizations they belong to."""

        async def work(token: str) -> dict[str, Any]:
            user = await forgejo.json("GET", "/user", token=token)
            orgs = await forgejo.all_pages("/user/orgs", token=token)
            return {
                "login": user.get("login"),
                "full_name": user.get("full_name"),
                "email": user.get("email"),
                "is_admin": user.get("is_admin"),
                "organizations": [o.get("username") or o.get("name") for o in orgs],
                "html_url": user.get("html_url"),
            }

        return await act("get_me", work)

    @server.tool(annotations=READ)
    async def search_repositories(
        query: Annotated[str, Field(max_length=255, description="Words to match in names (and descriptions).")] = "",
        include_archived: bool = False,
        page: PageNo = 1,
        limit: Limit = 20,
    ) -> dict[str, Any]:
        """Search the repositories this connection can see, most recently updated first."""

        async def work(token: str) -> dict[str, Any]:
            params: dict[str, Any] = {"q": query or None, "includeDesc": True, "sort": "updated", "order": "desc"}
            if not include_archived:
                params["archived"] = False
            result = await forgejo.page(
                "/repos/search", token=token, page=page, limit=limit, params=params, items_key="data"
            )
            return _page(result, _repo)

        return await act("search_repositories", work)

    @server.tool(annotations=READ)
    async def list_owner_repositories(owner: Owner, page: PageNo = 1, limit: Limit = 20) -> dict[str, Any]:
        """List the repositories of one user or organization that this connection can see."""

        async def work(token: str) -> dict[str, Any]:
            return _page(await forgejo.page(path("users", owner, "repos"), token=token, page=page, limit=limit), _repo)

        return await act("list_owner_repositories", work)

    @server.tool(annotations=READ)
    async def get_repository(owner: Owner, repo: Repo) -> dict[str, Any]:
        """One repository's details: default branch, visibility, counts and clone URLs."""

        async def work(token: str) -> dict[str, Any]:
            return _repo(await forgejo.json("GET", repo_path(owner, repo), token=token))

        return await act("get_repository", work)

    @server.tool(annotations=READ)
    async def list_branches(owner: Owner, repo: Repo, page: PageNo = 1, limit: Limit = 30) -> dict[str, Any]:
        """List a repository's branches with their latest commit."""

        def project(data: dict[str, Any]) -> dict[str, Any]:
            commit = data.get("commit") or {}
            return {
                "name": data.get("name"),
                "protected": data.get("protected"),
                "commit_sha": commit.get("id"),
                "commit_message": commit.get("message"),
                "commit_date": commit.get("timestamp"),
            }

        async def work(token: str) -> dict[str, Any]:
            result = await forgejo.page(repo_path(owner, repo, "branches"), token=token, page=page, limit=limit)
            return _page(result, project)

        return await act("list_branches", work)

    # ── Files and history ─────────────────────────────────────────────────────

    @server.tool(annotations=READ)
    async def list_directory(
        owner: Owner,
        repo: Repo,
        directory: Annotated[str, Field(max_length=4096, description="Directory path; empty for the root.")] = "",
        ref: Ref = None,
    ) -> dict[str, Any]:
        """List the files and folders in one directory of a repository."""

        async def work(token: str) -> dict[str, Any]:
            url = repo_path(owner, repo, "contents")
            if directory.strip("/"):
                url = f"{url}/{file_path(directory)}"
            data = await forgejo.json("GET", url, token=token, params={"ref": ref})
            if not isinstance(data, list):
                raise ToolError(f"'{directory}' is a file, not a directory. Use get_file to read it.")
            return {
                "path": directory.strip("/"),
                "entries": [
                    {"name": e.get("name"), "path": e.get("path"), "type": e.get("type"), "size": e.get("size")}
                    for e in data
                ],
            }

        return await act("list_directory", work)

    @server.tool(annotations=READ)
    async def get_file(
        owner: Owner,
        repo: Repo,
        file: Annotated[str, Field(min_length=1, max_length=4096, description="Path of the file in the repository.")],
        ref: Ref = None,
        start_line: Annotated[
            int | None, Field(default=None, ge=1, description="First line to return (1-based).")
        ] = None,
        end_line: Annotated[
            int | None, Field(default=None, ge=1, description="Last line to return, inclusive.")
        ] = None,
    ) -> dict[str, Any]:
        """Read a file. Returns the whole file unless a line range is given; total_lines says how long it is.

        The returned ``sha`` is what write_file needs to update this file.
        Binary files come back as base64.
        """
        if start_line is not None and end_line is not None and end_line < start_line:
            raise ToolError("end_line must not be before start_line")

        async def work(token: str) -> dict[str, Any]:
            url = f"{repo_path(owner, repo, 'contents')}/{file_path(file)}"
            data = await forgejo.json("GET", url, token=token, params={"ref": ref})
            if isinstance(data, list):
                raise ToolError(f"'{file}' is a directory. Use list_directory to see what it holds.")
            if data.get("type") == "symlink":
                return {
                    "path": data.get("path"),
                    "type": "symlink",
                    "target": data.get("target"),
                    "sha": data.get("sha"),
                }
            if data.get("type") == "submodule":
                return {"path": data.get("path"), "type": "submodule", "submodule_url": data.get("submodule_git_url")}
            text, binary = _decode_file(data)
            if text is None and binary is None:
                raw_url = f"{repo_path(owner, repo, 'raw')}/{file_path(file)}"
                text = await forgejo.text(raw_url, token=token, params={"ref": ref})
            result: dict[str, Any] = {
                "path": data.get("path"),
                "sha": data.get("sha"),
                "size": data.get("size"),
                "last_commit_sha": data.get("last_commit_sha"),
                "html_url": data.get("html_url"),
            }
            if binary is not None:
                result.update(encoding="base64", content=binary)
                return result
            assert text is not None
            lines = text.splitlines(keepends=True)
            result["total_lines"] = len(lines)
            if start_line is None and end_line is None:
                result["content"] = text
            else:
                first = (start_line or 1) - 1
                last = end_line or len(lines)
                result.update(start_line=first + 1, end_line=min(last, len(lines)), content="".join(lines[first:last]))
            result["encoding"] = "utf-8"
            return result

        return await act("get_file", work)

    @server.tool(annotations=READ)
    async def list_commits(
        owner: Owner,
        repo: Repo,
        ref: Ref = None,
        file: Annotated[
            str | None, Field(default=None, max_length=4096, description="Only commits touching this path.")
        ] = None,
        page: PageNo = 1,
        limit: Limit = 20,
    ) -> dict[str, Any]:
        """List commits, newest first, on a branch or ref and optionally for one path."""

        async def work(token: str) -> dict[str, Any]:
            params = {"sha": ref, "path": file, "stat": False, "verification": False, "files": False}
            result = await forgejo.page(
                repo_path(owner, repo, "commits"), token=token, page=page, limit=limit, params=params
            )
            return _page(result, _commit)

        return await act("list_commits", work)

    @server.tool(annotations=READ)
    async def get_commit(
        owner: Owner,
        repo: Repo,
        sha: Annotated[str, Field(min_length=4, max_length=64, description="Commit SHA (or a branch or tag).")],
        include_diff: bool = True,
    ) -> dict[str, Any]:
        """One commit: message, author, changed files and stats, and its full diff."""

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json("GET", repo_path(owner, repo, "git", "commits", sha), token=token)
            result = _commit(data)
            if include_diff:
                result["diff"] = await forgejo.text(
                    repo_path(owner, repo, "git", "commits", f"{sha}.diff"), token=token
                )
            return result

        return await act("get_commit", work)

    @server.tool(annotations=READ)
    async def compare(
        owner: Owner,
        repo: Repo,
        base: Annotated[str, Field(min_length=1, max_length=255, description="Base branch, tag or SHA.")],
        head: Annotated[str, Field(min_length=1, max_length=255, description="Head branch, tag or SHA.")],
    ) -> dict[str, Any]:
        """The commits and changed files between two refs."""

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json("GET", repo_path(owner, repo, "compare", f"{base}...{head}"), token=token)
            return {
                "total_commits": data.get("total_commits"),
                "commits": [_commit(c) for c in data.get("commits") or []],
                "files": [
                    {
                        "filename": f.get("filename"),
                        "status": f.get("status"),
                        "additions": f.get("additions"),
                        "deletions": f.get("deletions"),
                    }
                    for f in data.get("files") or []
                ],
            }

        return await act("compare", work)

    # ── Issues and pull requests ──────────────────────────────────────────────

    @server.tool(annotations=READ)
    async def search_issues(
        query: Annotated[str, Field(max_length=255, description="Words to match in titles and bodies.")] = "",
        state: IssueState = "open",
        kind: Literal["issues", "pulls", "all"] = "all",
        involving_me: Annotated[
            Literal["any", "assigned", "created", "mentioned", "review_requested"],
            Field(description="Limit to items related to the caller in this way."),
        ] = "any",
        page: PageNo = 1,
        limit: Limit = 20,
    ) -> dict[str, Any]:
        """Search issues and pull requests across every repository this connection can see."""

        async def work(token: str) -> dict[str, Any]:
            params: dict[str, Any] = {
                "q": query or None,
                "state": state,
                "type": None if kind == "all" else kind,
                "sort": "recentupdate",
            }
            if involving_me != "any":
                params[involving_me] = True
            result = await forgejo.page("/repos/issues/search", token=token, page=page, limit=limit, params=params)
            return _page(result, lambda d: _issue(d, with_body=False))

        return await act("search_issues", work)

    @server.tool(annotations=READ)
    async def list_issues(
        owner: Owner,
        repo: Repo,
        state: IssueState = "open",
        labels: Annotated[
            str | None, Field(default=None, max_length=1024, description="Comma-separated label names.")
        ] = None,
        query: Annotated[str | None, Field(default=None, max_length=255, description="Words to match.")] = None,
        page: PageNo = 1,
        limit: Limit = 20,
    ) -> dict[str, Any]:
        """List a repository's issues (not pull requests), most recently updated first."""

        async def work(token: str) -> dict[str, Any]:
            params = {"state": state, "labels": labels, "q": query, "type": "issues", "sort": "recentupdate"}
            result = await forgejo.page(
                repo_path(owner, repo, "issues"), token=token, page=page, limit=limit, params=params
            )
            return _page(result, lambda d: _issue(d, with_body=False))

        return await act("list_issues", work)

    @server.tool(annotations=READ)
    async def get_issue(owner: Owner, repo: Repo, number: Number, include_comments: bool = True) -> dict[str, Any]:
        """One issue or pull request conversation: body, labels, state and every comment."""

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json("GET", repo_path(owner, repo, "issues", number), token=token)
            result = _issue(data, with_body=True)
            if include_comments:
                comments = await forgejo.json("GET", repo_path(owner, repo, "issues", number, "comments"), token=token)
                result["comment_thread"] = [_comment(c) for c in comments or []]
            return result

        return await act("get_issue", work)

    @server.tool(annotations=READ)
    async def list_pull_requests(
        owner: Owner,
        repo: Repo,
        state: IssueState = "open",
        page: PageNo = 1,
        limit: Limit = 20,
    ) -> dict[str, Any]:
        """List a repository's pull requests, most recently updated first."""

        async def work(token: str) -> dict[str, Any]:
            result = await forgejo.page(
                repo_path(owner, repo, "pulls"),
                token=token,
                page=page,
                limit=limit,
                params={"state": state, "sort": "recentupdate"},
            )
            return _page(result, lambda d: _pull(d, with_body=False))

        return await act("list_pull_requests", work)

    @server.tool(annotations=READ)
    async def get_pull_request(owner: Owner, repo: Repo, number: Number, include_diff: bool = False) -> dict[str, Any]:
        """One pull request: description, branches, mergeability, changed files, reviews, and optionally the diff.

        Use get_issue with the same number for the comment thread.
        """

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json("GET", repo_path(owner, repo, "pulls", number), token=token)
            files = await forgejo.all_pages(repo_path(owner, repo, "pulls", number, "files"), token=token)
            reviews = await forgejo.all_pages(repo_path(owner, repo, "pulls", number, "reviews"), token=token)
            result = _pull(data, with_body=True)
            result["files"] = [
                {
                    "filename": f.get("filename"),
                    "status": f.get("status"),
                    "additions": f.get("additions"),
                    "deletions": f.get("deletions"),
                }
                for f in files
            ]
            result["reviews"] = [
                {
                    "reviewer": _user(r.get("user")),
                    "state": r.get("state"),
                    "body": r.get("body") or "",
                    "submitted_at": r.get("submitted_at"),
                }
                for r in reviews
            ]
            if include_diff:
                result["diff"] = await forgejo.text(repo_path(owner, repo, "pulls", f"{number}.diff"), token=token)
            return result

        return await act("get_pull_request", work)

    @server.tool(annotations=READ)
    async def list_action_runs(
        owner: Owner,
        repo: Repo,
        status: Annotated[
            Literal["unknown", "waiting", "running", "success", "failure", "cancelled", "skipped", "blocked"] | None,
            Field(default=None, description="Only runs in this status."),
        ] = None,
        ref: Ref = None,
        page: PageNo = 1,
        limit: Limit = 20,
    ) -> dict[str, Any]:
        """List Forgejo Actions workflow runs for a repository, newest first."""

        async def work(token: str) -> dict[str, Any]:
            params = {"status": [status] if status else None, "ref": ref}
            try:
                result = await forgejo.page(
                    repo_path(owner, repo, "actions", "runs"),
                    token=token,
                    page=page,
                    limit=limit,
                    params=params,
                    items_key="workflow_runs",
                )
            except ForgejoError as exc:
                if exc.status == 404:
                    raise ToolError(
                        "Forgejo returned 404: the repository doesn't exist, the token can't see it, "
                        "or Actions is turned off for it."
                    ) from None
                raise
            return _page(result, _run)

        return await act("list_action_runs", work)

    @server.tool(annotations=READ)
    async def list_releases(owner: Owner, repo: Repo, page: PageNo = 1, limit: Limit = 10) -> dict[str, Any]:
        """List a repository's releases, newest first, with notes and assets."""

        async def work(token: str) -> dict[str, Any]:
            return _page(
                await forgejo.page(repo_path(owner, repo, "releases"), token=token, page=page, limit=limit), _release
            )

        return await act("list_releases", work)

    # ── Writes ────────────────────────────────────────────────────────────────

    @server.tool(annotations=ADD)
    async def create_issue(
        owner: Owner,
        repo: Repo,
        title: Annotated[str, Field(min_length=1, max_length=255)],
        body: Annotated[str, Field(max_length=65535, description="Markdown.")] = "",
        assignees: Annotated[
            list[str] | None, Field(default=None, max_length=20, description="Logins to assign.")
        ] = None,
    ) -> dict[str, Any]:
        """Open a new issue."""

        async def work(token: str) -> dict[str, Any]:
            payload: dict[str, Any] = {"title": title, "body": body}
            if assignees:
                payload["assignees"] = assignees
            return _issue(
                await forgejo.json("POST", repo_path(owner, repo, "issues"), token=token, body=payload), with_body=True
            )

        return await act("create_issue", work)

    @server.tool(annotations=CHANGE)
    async def update_issue(
        owner: Owner,
        repo: Repo,
        number: Number,
        title: Annotated[str | None, Field(default=None, min_length=1, max_length=255)] = None,
        body: Annotated[
            str | None, Field(default=None, max_length=65535, description="Replaces the whole body.")
        ] = None,
        state: Literal["open", "closed"] | None = None,
    ) -> dict[str, Any]:
        """Change an issue's or pull request's title, body, or open/closed state."""
        payload = {k: v for k, v in {"title": title, "body": body, "state": state}.items() if v is not None}
        if not payload:
            raise ToolError("Nothing to change: give a title, body or state.")

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json("PATCH", repo_path(owner, repo, "issues", number), token=token, body=payload)
            return _issue(data, with_body=True)

        return await act("update_issue", work)

    @server.tool(annotations=ADD)
    async def add_comment(
        owner: Owner,
        repo: Repo,
        number: Number,
        body: Annotated[str, Field(min_length=1, max_length=65535, description="Markdown.")],
    ) -> dict[str, Any]:
        """Comment on an issue or pull request."""

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json(
                "POST", repo_path(owner, repo, "issues", number, "comments"), token=token, body={"body": body}
            )
            return _comment(data)

        return await act("add_comment", work)

    @server.tool(annotations=ADD)
    async def create_branch(
        owner: Owner,
        repo: Repo,
        name: Annotated[str, Field(min_length=1, max_length=255, description="New branch name.")],
        from_ref: Annotated[
            str | None,
            Field(
                default=None,
                max_length=255,
                description="Branch, tag or SHA to start from. Default branch when omitted.",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create a branch."""

        async def work(token: str) -> dict[str, Any]:
            payload: dict[str, Any] = {"new_branch_name": name}
            if from_ref:
                payload["old_ref_name"] = from_ref
            data = await forgejo.json("POST", repo_path(owner, repo, "branches"), token=token, body=payload)
            return {"name": data.get("name"), "commit_sha": (data.get("commit") or {}).get("id")}

        return await act("create_branch", work)

    @server.tool(annotations=CHANGE)
    async def write_file(
        owner: Owner,
        repo: Repo,
        file: Annotated[str, Field(min_length=1, max_length=4096, description="Path of the file in the repository.")],
        content: Annotated[str, Field(description="The complete new file contents (UTF-8 text).")],
        message: Annotated[str, Field(min_length=1, max_length=65535, description="Commit message.")],
        branch: Annotated[
            str | None,
            Field(default=None, max_length=255, description="Branch to commit to. Default branch when omitted."),
        ] = None,
        new_branch: Annotated[
            str | None,
            Field(default=None, max_length=255, description="Create this branch from `branch` and commit there."),
        ] = None,
        sha: Annotated[
            str | None,
            Field(
                default=None,
                max_length=64,
                description="The file's current sha from get_file. Required to update an existing file; "
                "omit it to create a new one.",
            ),
        ] = None,
    ) -> dict[str, Any]:
        """Create or replace one file in a single commit.

        To change an existing file, read it with get_file first and pass its ``sha``:
        Forgejo refuses the write if the file changed since, so nothing is overwritten blind.
        """

        async def work(token: str) -> dict[str, Any]:
            payload: dict[str, Any] = {
                "content": base64.b64encode(content.encode()).decode(),
                "message": message,
            }
            if branch:
                payload["branch"] = branch
            if new_branch:
                payload["new_branch"] = new_branch
            url = f"{repo_path(owner, repo, 'contents')}/{file_path(file)}"
            if sha:
                payload["sha"] = sha
                data = await forgejo.json("PUT", url, token=token, body=payload)
            else:
                data = await forgejo.json("POST", url, token=token, body=payload)
            written = data.get("content") or {}
            commit = data.get("commit") or {}
            return {
                "path": written.get("path"),
                "sha": written.get("sha"),
                "commit_sha": commit.get("sha"),
                "commit_url": commit.get("html_url"),
            }

        return await act("write_file", work)

    @server.tool(annotations=ADD)
    async def create_pull_request(
        owner: Owner,
        repo: Repo,
        title: Annotated[str, Field(min_length=1, max_length=255)],
        head: Annotated[str, Field(min_length=1, max_length=255, description="Branch with the changes.")],
        base: Annotated[str, Field(min_length=1, max_length=255, description="Branch to merge into.")],
        body: Annotated[str, Field(max_length=65535, description="Markdown description.")] = "",
    ) -> dict[str, Any]:
        """Open a pull request from one branch into another."""

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json(
                "POST",
                repo_path(owner, repo, "pulls"),
                token=token,
                body={"title": title, "head": head, "base": base, "body": body},
            )
            return _pull(data, with_body=True)

        return await act("create_pull_request", work)

    @server.tool(annotations=ADD)
    async def review_pull_request(
        owner: Owner,
        repo: Repo,
        number: Number,
        event: Literal["APPROVED", "REQUEST_CHANGES", "COMMENT"],
        body: Annotated[str, Field(max_length=65535, description="Review summary (Markdown).")] = "",
    ) -> dict[str, Any]:
        """Submit a review on a pull request: approve, request changes, or comment."""
        if event != "APPROVED" and not body.strip():
            raise ToolError("A review that requests changes or comments needs a body.")

        async def work(token: str) -> dict[str, Any]:
            data = await forgejo.json(
                "POST",
                repo_path(owner, repo, "pulls", number, "reviews"),
                token=token,
                body={"event": event, "body": body},
            )
            return {"id": data.get("id"), "state": data.get("state"), "html_url": data.get("html_url")}

        return await act("review_pull_request", work)

    @server.tool(annotations=CHANGE)
    async def merge_pull_request(
        owner: Owner,
        repo: Repo,
        number: Number,
        method: Literal["merge", "rebase", "rebase-merge", "squash", "fast-forward-only"] = "merge",
        head_sha: Annotated[
            str | None,
            Field(
                default=None,
                max_length=64,
                description="Merge only if the PR head is still this commit (from get_pull_request).",
            ),
        ] = None,
        message: Annotated[
            str | None, Field(default=None, max_length=65535, description="Merge commit message.")
        ] = None,
        delete_branch: bool = False,
    ) -> dict[str, Any]:
        """Merge a pull request. Pass head_sha so nothing pushed after review gets merged unseen."""

        async def work(token: str) -> dict[str, Any]:
            payload: dict[str, Any] = {"Do": method, "delete_branch_after_merge": delete_branch}
            if head_sha:
                payload["head_commit_id"] = head_sha
            if message:
                payload["MergeMessageField"] = message
            url = repo_path(owner, repo, "pulls", number, "merge")
            # Forgejo checks mergeability in the background after a push and answers 405 "try again
            # later" until it is done. A 405 means nothing was merged, so trying again is safe.
            for attempt in range(MERGE_ATTEMPTS):
                try:
                    await forgejo.json("POST", url, token=token, body=payload)
                    break
                except ForgejoError as exc:
                    still_checking = exc.status == 405 and "try again later" in str(exc).lower()
                    if not still_checking or attempt == MERGE_ATTEMPTS - 1:
                        raise
                    await asyncio.sleep(MERGE_RETRY_SECONDS * (attempt + 1))
            data = await forgejo.json("GET", repo_path(owner, repo, "pulls", number), token=token)
            return _pull(data, with_body=False)

        return await act("merge_pull_request", work)
