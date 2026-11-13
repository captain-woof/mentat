from requests import Session
from requests_ratelimiter import LimiterAdapter
from os import environ, mkdir, path
import subprocess
import sys
import json
import shutil
import base64

# Credentials and session objects (configured in setupGithubSessions, called from gather)
githubPatToken = ""
session = None
sessionSlow = None

def setupGithubSessions(patToken):
    global githubPatToken, session, sessionSlow
    githubPatToken = patToken

    # Create session objects and configure for all web requests
    session = Session()
    adapter = LimiterAdapter(per_minute=30)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    session.headers.update({
        "Authorization": f"Bearer {githubPatToken}",
        "X-GitHub-Api-Version": "2026-03-10",
        "Accept": "application/vnd.github.text-match+json"
    })

    sessionSlow = Session()
    adapterSlow = LimiterAdapter(per_minute=10)
    sessionSlow.mount('http://', adapterSlow)
    sessionSlow.mount('https://', adapterSlow)
    sessionSlow.headers.update({
        "Authorization": f"Bearer {githubPatToken}",
        "X-GitHub-Api-Version": "2026-03-10",
        "Accept": "application/vnd.github.text-match+json"
    })

# ANSI colour codes for STDOUT
ANSI_RESET = "\x1b[0m"
ANSI_BOLD = "\x1b[1m"
ANSI_RED = "\x1b[31m"
ANSI_GREEN = "\x1b[32m"
ANSI_YELLOW = "\x1b[33m"
ANSI_BLUE = "\x1b[34m"
ANSI_CYAN = "\x1b[36m"

# Whether STDOUT gets colours; the log file always stays plain (set by setupOutputFormatting, called from gather)
useColor = False

def setupOutputFormatting(noColor):
    global useColor
    # Dynamically fall back to no colour if STDOUT is not a real terminal
    # (pipe, redirect, CI, ...), if NO_COLOR is set, or if the terminal is too dumb
    useColor = (not noColor) and hasattr(sys.stdout, "isatty") and sys.stdout.isatty() and environ.get("NO_COLOR", "") == "" and environ.get("TERM", "dumb") != "dumb"

def printError(text):
    # Errors from helper functions are only printed (callers log outcomes via logText); red when colour is on
    if useColor:
        print(f"{ANSI_RED}{text}{ANSI_RESET}")
    else:
        print(text)

# Assisting functions
def makeHumanReadableTrufflehogReport(jsonResultsPath, reportPath, stderrText):
    # Reads Trufflehog's --json output (one JSON object per line) and writes
    # a human-readable report with the same base name next to it
    findingsCount = 0
    with open(reportPath, "a") as reportFile:
        try:
            with open(jsonResultsPath, "r") as jsonResultsFile:
                for line in jsonResultsFile:
                    line = line.strip()
                    if line == "":
                        continue
                    try:
                        finding = json.loads(line)
                    except Exception:
                        continue

                    sourceData = finding.get("SourceMetadata", {}).get("Data", {})
                    sourceGit = sourceData.get("Git", {})
                    sourceFilesystem = sourceData.get("Filesystem", {})
                    findingsCount += 1

                    reportFile.write(f"""================================
Detector: {finding.get("DetectorName", "")} (type: {finding.get("DetectorType", "")}, decoder: {finding.get("DecoderName", "")}) | Verified: {finding.get("Verified", "")}
Repository: {sourceGit.get("repository", "")} | File: {sourceGit.get("file", sourceFilesystem.get("file", ""))} | Line: {sourceGit.get("line", sourceFilesystem.get("line", ""))}
Commit: {sourceGit.get("commit", "")} | Link: {sourceGit.get("link", "")}
Raw: {finding.get("Raw", "")}

""")
                reportFile.flush()
        except FileNotFoundError:
            reportFile.write(f"[!] No JSON results found at '{jsonResultsPath}'\n")

        reportFile.write(f"------------\n# STDERR LOG:\n------------\n{stderrText}\n")
        reportFile.flush()

    return findingsCount

def runTrufflehog(outputDir, repositoriesToSearchIn, logText):
    # Trufflehog binary is required for scanning; without it, just move on (all data is already saved)
    if shutil.which("trufflehog") == None:
        logText("'trufflehog' binary not found in PATH; skipping all trufflehog scans", kind="error")
        return

    # Create results dir OUTSIDE of outputDir, so that filesystem mode does not scan
    # Trufflehog's own results; moved into outputDir when all scans are done
    trufflehogTempDir = path.normpath(outputDir) + "_temp"
    trufflehogDir = path.join(trufflehogTempDir, "trufflehog-results")
    try:
        mkdir(trufflehogTempDir)
    except FileExistsError:
        pass
    except Exception as e:
        logText(f"Could not create directory '{trufflehogTempDir}'; error: {e}", level=1, kind="error")
    try:
        mkdir(trufflehogDir)
    except FileExistsError:
        pass
    except Exception as e:
        logText(f"Could not create directory '{trufflehogDir}'; error: {e}", level=1, kind="error")

    logText("")
    logText("Running Trufflehog on all repositories...", kind="stage")

    # Run in Local Git mode
    for repositoryToSearchIn in repositoriesToSearchIn:
        gitDir = path.join(outputDir, "repos", repositoryToSearchIn["full_name"].replace("/", "__"), repositoryToSearchIn["name"])

        # Repo may not have been cloned (e.g. private repo without access); skip instead of scanning nothing
        if not path.exists(gitDir):
            logText(f"Skipping trufflehog git scan for '{repositoryToSearchIn["full_name"]}': no local clone at '{gitDir}'", level=1, kind="error")
            continue

        trufflehogRepoResultsJsonPath = path.join(trufflehogDir, f"{repositoryToSearchIn["full_name"].replace("/", "__")}.json")
        trufflehogRepoResultsReportPath = path.join(trufflehogDir, f"{repositoryToSearchIn["full_name"].replace("/", "__")}.human-readable.txt")

        try:
            p = subprocess.Popen(
                args=[
                    "trufflehog",
                    "git",
                    "--json",
                    "--no-verification",
                    "--no-update",
                    f"--config=rules-trufflehogv3.yml",
                    f"file://{gitDir}"
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = p.communicate()
        except Exception as e:
            logText(f"Failed to run trufflehog on repo '{repositoryToSearchIn["full_name"]}'; error: {e}", level=1, kind="error")
            continue

        with open(trufflehogRepoResultsJsonPath, "a") as trufflehogRepoResultsFile:
            trufflehogRepoResultsFile.write(stdout)
            trufflehogRepoResultsFile.flush()

        findingsCount = makeHumanReadableTrufflehogReport(
            jsonResultsPath=trufflehogRepoResultsJsonPath,
            reportPath=trufflehogRepoResultsReportPath,
            stderrText=stderr
        )

        logText(f"Repo '{repositoryToSearchIn["full_name"]}': {findingsCount} findings; results in '{trufflehogRepoResultsJsonPath}'", level=1, kind="success")

    # Run in filesystem mode
    trufflehogFilesystemResultsJsonPath = path.join(trufflehogDir, "results-from-all-filesystem-files-here.json")
    trufflehogFilesystemResultsReportPath = path.join(trufflehogDir, "results-from-all-filesystem-files-here.human-readable.txt")

    try:
        p = subprocess.Popen(
            args=[
                "trufflehog",
                "filesystem",
                "--json",
                "--no-verification",
                "--no-update",
                f"--config=rules-trufflehogv3.yml",
                outputDir
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
    except Exception as e:
        logText(f"Failed to run trufflehog in filesystem mode; error: {e}", level=1, kind="error")
        stdout, stderr = "", ""

    with open(trufflehogFilesystemResultsJsonPath, "a") as trufflehogFilesystemResultsFile:
        trufflehogFilesystemResultsFile.write(stdout)
        trufflehogFilesystemResultsFile.flush()

    findingsCount = makeHumanReadableTrufflehogReport(
        jsonResultsPath=trufflehogFilesystemResultsJsonPath,
        reportPath=trufflehogFilesystemResultsReportPath,
        stderrText=stderr
    )

    logText(f"Filesystem scan of everything: {findingsCount} findings; results in '{trufflehogFilesystemResultsJsonPath}'", level=1, kind="success")

    # All scans done: move results from the temp dir into outputDir
    trufflehogFinalDir = path.join(outputDir, "trufflehog-results")
    try:
        if path.exists(trufflehogFinalDir):
            shutil.rmtree(trufflehogFinalDir)
        shutil.move(trufflehogDir, trufflehogFinalDir)
        try:
            shutil.rmtree(trufflehogTempDir)
        except Exception:
            pass
        logText(f"Moved all trufflehog results to '{trufflehogFinalDir}'", level=1, kind="success")
    except Exception as e:
        logText(f"Failed to move trufflehog results into '{outputDir}'; results left at '{trufflehogDir}'; error: {e}", level=1, kind="error")

def cloneRepository(gitRepositoryCloneUrl, gitRepositorySavePath):
    # Pass the PAT as a per-command HTTP header so that private repos accessible to the token
    # can also be cloned; unlike embedding it in the URL, the token is NOT written into
    # the clone's .git/config or reflogs. It is still briefly visible in the process list.
    basicAuthHeader = base64.b64encode(f"x-access-token:{githubPatToken}".encode()).decode()
    try:
        p = subprocess.Popen(
            args=[
                "git",
                "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: Basic {basicAuthHeader}",
                "clone",
                gitRepositoryCloneUrl,
                gitRepositorySavePath
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
    except Exception as e:
        printError(f"[!] Failed to run git clone for '{gitRepositoryCloneUrl}'; error: {e}")
        return ("", str(e), 1)

    if p.returncode != 0:
        printError(f"[!] Failed to clone '{gitRepositoryCloneUrl}'; error: {stderr.strip()}")

    return (stdout, stderr, p.returncode)

def saveCode(repoSaveDirPath, resultsFromCodeSearch):
    codeDirPath = path.join(repoSaveDirPath, "code-search")
    try:
        mkdir(codeDirPath)
    except FileExistsError:
        pass
    except Exception as e:
        printError(f"[!] Could not create directory '{codeDirPath}'; error: {e}")

    for resultFromCodeSearch in resultsFromCodeSearch:
        try:
            repoFullName = resultFromCodeSearch["repository"]["full_name"]
            filePath = resultFromCodeSearch["path"]
            htmlUrl = resultFromCodeSearch["html_url"]
            sha = resultFromCodeSearch["sha"]
            textMatches = resultFromCodeSearch["text_matches"]

            textMatchesContents = ""
            for i, textMatch in enumerate(textMatches):
                textMatchesContents += f"""Match #{i+1}

URL: {textMatch["object_url"]}
>>>>>>>>>>>>>>>>>>>>>>>>>>>>
{textMatch["fragment"]}
>>>>>>>>>>>>>>>>>>>>>>>>>>>>
"""

                codePath = path.join(codeDirPath, f"{repoFullName}_{filePath}_{sha}.md")
                codeContents = f"""# Code {filePath}

------------
# URL: {htmlUrl}
------------
# EVIDENCE CHAIN:
{resultFromCodeSearch.get("evidenceChain", [])}
------------
# RESULTS:
------------
Repository: {repoFullName}
Filename: {filePath}
SHA: {sha}
------------
# MATCHES:
------------
{textMatchesContents}
"""
            with open(codePath, "a") as codeFile:
                codeFile.write(codeContents)
                codeFile.flush()
        except Exception as e:
            printError(f"[!] Failed to save a code search result; error: {e}")

def saveGists(projectDirPath, gistsList = []):
    gistsPath = path.join(projectDirPath, "gists")
    try:
        mkdir(gistsPath)
    except FileExistsError:
        pass
    except Exception as e:
        printError(f"[!] Could not create directory '{gistsPath}'; error: {e}")

    for gist in gistsList:
        try:
            gistDetails = gist.get("gistDetails", {})
            if gistDetails == {}:
                printError(f"[!] Skipping a gist: no details were downloaded")
                continue
            gistOwnerLogin = (gistDetails.get("owner") or {}).get("login", "anonymous")
            gistPath = path.join(gistsPath, f"{gistOwnerLogin}_{gistDetails.get("id", "unknown")}.md")

            gistContents = f"""# Gist {gistDetails.get("id", "unknown")}

------------
# URL: {gistDetails.get("html_url", "")}
------------
# EVIDENCE CHAIN:
{gist.get("evidenceChain", [])}
------------
# CONTENTS:
------------
{"".join([f"{gistFileAndContent.get("filename", "unknown")}\n{gistFileAndContent.get("content", "")}\n\n" for gistFileAndContent in gistDetails.get("files", {}).values()])}

"""
            with open(gistPath, "a") as gistFile:
                gistFile.write(gistContents)
                gistFile.flush()
        except Exception as e:
            printError(f"[!] Failed to save a gist; error: {e}")

def savePullRequests(repoSaveDirPath, pullRequestsList = []):
    pullRequestsPath = path.join(repoSaveDirPath, "PRs")
    try:
        mkdir(pullRequestsPath)
    except FileExistsError:
        pass
    except Exception as e:
        printError(f"[!] Could not create directory '{pullRequestsPath}'; error: {e}")

    for pullRequest in pullRequestsList:
        try:
            patchDetails = pullRequest.get("patchDetails", "")

            pullRequestUserLogin = (pullRequest.get("user") or {}).get("login", "unknown")
            pullRequestPath = path.join(pullRequestsPath, f"{pullRequestUserLogin}_{pullRequest.get("id", "unknown")}")

            pullRequestContents = f"""# PR {pullRequest.get("id", "unknown")}

------------
# URL: {pullRequest.get("html_url", "")}
------------
# EVIDENCE CHAIN:
{pullRequest.get("evidenceChain", [])}
------------
# BODY:
------------
{pullRequest.get("body") or ""}
--------------
# PATCH DETAILS:
--------------
{patchDetails}

"""
            with open(pullRequestPath, "a") as prFile:
                prFile.write(pullRequestContents)
                prFile.flush()
        except Exception as e:
            printError(f"[!] Failed to save a PR; error: {e}")


def saveCommits(repoSaveDirPath, commitsList = []):
    commitsPath = path.join(repoSaveDirPath, "commits")
    try:
        mkdir(commitsPath)
    except FileExistsError:
        pass
    except Exception as e:
        printError(f"[!] Could not create directory '{commitsPath}'; error: {e}")

    for commit in commitsList:
        try:
            commitDetails = commit.get("commitDetails", {"files": []})

            # Author is null for commits whose author is not a GitHub account (email-only, deleted, etc.)
            commitAuthorLogin = (commit.get("author") or {}).get("login", "unknown")
            commitPath = path.join(commitsPath, f"{commitAuthorLogin}_{commit.get("sha", "unknown")}")

            pullRequestContents = f"""# Commit {commit.get("sha", "unknown")}

-----------------
# URL: {commit.get("html_url", "")}
-----------------
# EVIDENCE CHAIN:
{commit.get("evidenceChain", [])}
-----------------
# COMMIT MESSAGE:
-----------------
{commit.get("commit", {}).get("message", "")}
-----------------
# COMMIT DETAILS:
-----------------
{"".join([f"{file.get("filename", "unknown")}\n{file.get("patch", "[no patch available - binary file or patch too large]")}\n\n" for file in commitDetails.get("files", [])])}

"""
            with open(commitPath, "a") as prFile:
                prFile.write(pullRequestContents)
                prFile.flush()
        except Exception as e:
            printError(f"[!] Failed to save a commit; error: {e}")

def saveCommitComments(repoSaveDirPath, commitCommentsList = []):
    commitCommentsPath = path.join(repoSaveDirPath, "commit-comments")
    try:
        mkdir(commitCommentsPath)
    except FileExistsError:
        pass
    except Exception as e:
        printError(f"[!] Could not create directory '{commitCommentsPath}'; error: {e}")

    for commitComment in commitCommentsList:
        try:
            commitCommentUserLogin = (commitComment.get("user") or {}).get("login", "unknown")
            commitCommentPath = path.join(commitCommentsPath, f"{commitCommentUserLogin}_{commitComment.get("id", "unknown")}")

            commitCommentContents = f"""# Commit comment {commitComment.get("id", "unknown")}

-----------------
# URL: {commitComment.get("html_url", "")}
-----------------
# EVIDENCE CHAIN:
{commitComment.get("evidenceChain", [])}
-----------------
# COMMIT ID:
{commitComment.get("commit_id", "")}
-----------------
# COMMIT COMMENT:
-----------------
@{commitCommentUserLogin} says on file {commitComment.get("path", "")}, line {commitComment.get("line", "")}, position {commitComment.get("position", "")}:
{commitComment.get("body") or ""}

"""
            with open(commitCommentPath, "a") as commitCommentsFile:
                commitCommentsFile.write(commitCommentContents)
                commitCommentsFile.flush()
        except Exception as e:
            printError(f"[!] Failed to save a commit comment; error: {e}")

def saveIssues(repoSaveDirPath, issuesList = []):
    issuesPath = path.join(repoSaveDirPath, "issues")
    try:
        mkdir(issuesPath)
    except FileExistsError:
        pass
    except Exception as e:
        printError(f"[!] Could not create directory '{issuesPath}'; error: {e}")

    for issue in issuesList:
        try:
            issueUserLogin = (issue.get("user") or {}).get("login", "unknown")
            issuePath = path.join(issuesPath, f"{issueUserLogin}_{issue.get("id", "unknown")}")

            issueContents = f"""# Issue {issue.get("id", "unknown")}

-----------------
# URL: {issue.get("html_url", "")}
-----------------
# EVIDENCE CHAIN:
{issue.get("evidenceChain", [])}
-----------------
# ISSUE:
Raised by @{issueUserLogin}

# {issue.get("title", "")}

{issue.get("body") or ""}

"""
            with open(issuePath, "a") as issueFile:
                issueFile.write(issueContents)
                issueFile.flush()
        except Exception as e:
            printError(f"[!] Failed to save an issue; error: {e}")

def saveIssueComments(repoSaveDirPath, issueCommentsList = []):
    issueComments = path.join(repoSaveDirPath, "issue-comments")
    try:
        mkdir(issueComments)
    except FileExistsError:
        pass
    except Exception as e:
        printError(f"[!] Could not create directory '{issueComments}'; error: {e}")

    for issueComment in issueCommentsList:
        try:
            issueCommentUserLogin = (issueComment.get("user") or {}).get("login", "unknown")
            issueCommentPath = path.join(issueComments, f"{issueCommentUserLogin}_{issueComment.get("id", "unknown")}")

            issueContents = f"""# Issue {issueComment.get("id", "unknown")}

-----------------
# ISSUE URL: {issueComment.get("issue_url", "")}
# COMMENT URL: {issueComment.get("html_url", "")}
-----------------
# EVIDENCE CHAIN:
{issueComment.get("evidenceChain", [])}
-----------------
# ISSUE COMMENT:
@{issueCommentUserLogin} says:
{issueComment.get("body") or ""}

"""
            with open(issueCommentPath, "a") as issueFile:
                issueFile.write(issueContents)
                issueFile.flush()
        except Exception as e:
            printError(f"[!] Failed to save an issue comment; error: {e}")

def getPullRequests(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url=f"https://api.github.com/repos/{repoFullName}/pulls",
                    params={
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for PRs of repository '{repoFullName}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
            except Exception as e:
                printError(f"[!] Could not parse PRs response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            printError(f"[!] Failed to get PRs of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break

    # Get the actual PR itself
    for i in range (0, len(allItems)):
        try:
            url = allItems[i].get("patch_url") or allItems[i].get("diff_url", "")
            if url == "":
                allItems[i]["patchDetails"] = ""
                continue
            response = session.get(
                url=url
            )
            allItems[i]["patchDetails"] = response.text
        except Exception as e:
            printError(f"[!] Failed to get patch details of a PR in repository '{repoFullName}'; error: {e}")
            allItems[i]["patchDetails"] = ""
    return allItems

def getIssues(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url=f"https://api.github.com/repos/{repoFullName}/issues",
                    params={
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for issues of repository '{repoFullName}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
            except Exception as e:
                printError(f"[!] Could not parse issues response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            printError(f"[!] Failed to get issues of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def getIssueComments(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url=f"https://api.github.com/repos/{repoFullName}/issues/comments",
                    params={
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for issue comments of repository '{repoFullName}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
            except Exception as e:
                printError(f"[!] Could not parse issue comments response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            printError(f"[!] Failed to get issue comments of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def getCommitComments(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url=f"https://api.github.com/repos/{repoFullName}/comments",
                    params={
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for commit comments of repository '{repoFullName}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
            except Exception as e:
                printError(f"[!] Could not parse commit comments response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            printError(f"[!] Failed to get commit comments of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def getForks(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url=f"https://api.github.com/repos/{repoFullName}/forks",
                    params={
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for forks of repository '{repoFullName}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
            except Exception as e:
                printError(f"[!] Could not parse forks response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            printError(f"[!] Failed to get forks of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def getGists(userOrOrgName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url=f"https://api.github.com/users/{userOrOrgName}/gists",
                    params={
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for gists of user/organisation '{userOrOrgName}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
            except Exception as e:
                printError(f"[!] Could not parse gists response for user/organisation '{userOrOrgName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            printError(f"[!] Failed to get gists of user/organisation '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break

    # Get the actual gist itself
    for i in range (0, len(allItems)):
        try:
            response = session.get(
                url=allItems[i]["url"]
            )
            responseJson = response.json()
            allItems[i]["gistDetails"] = responseJson
        except Exception as e:
            printError(f"[!] Failed to get details of a gist of user/organisation '{userOrOrgName}'; error: {e}")
            allItems[i]["gistDetails"] = {}
    return allItems

def getContributorsOfARepository(contributorsUrl):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url=contributorsUrl,
                    params={
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for contributors '{contributorsUrl}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
            except Exception as e:
                printError(f"[!] Could not parse contributors response '{contributorsUrl}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            printError(f"[!] Failed to get contributors '{contributorsUrl}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def getReposOwnedByUserOrOrg(userOrOrgName, isUser = True):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url="https://api.github.com/search/repositories",
                    params={
                        "q": f"{"user" if isUser else "org"}:{userOrOrgName} fork:true",
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for repositories owned by '{userOrOrgName}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
                items = responseJson["items"]
            except Exception as e:
                printError(f"[!] Could not parse repositories response for '{userOrOrgName}'; error: {e}")
                break
            allItems.extend(items)
        else:
            printError(f"[!] Failed to get repositories owned by '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def getReposFromCodeSearch(searchTerm):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    # Search in code
    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = sessionSlow.get(
                    url="https://api.github.com/search/code",
                    params={
                        "q": f"{searchTerm} in:file,path",
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = sessionSlow.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for repositories matching code search term '{searchTerm}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
                items = responseJson["items"]
            except Exception as e:
                printError(f"[!] Could not parse repositories response for code search term '{searchTerm}'; error: {e}")
                break
            allItems.extend(items)
        else:
            printError(f"[!] Failed to get repositories matching code search term '{searchTerm}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    
    return allItems

def getReposFromNameSearchTerm(searchTerm):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    # Search in repositories
    while True:
        # Make first request to get first batch of data and pagination information
        try:
            if not isStartingFromPage2:
                response = session.get(
                    url="https://api.github.com/search/repositories",
                    params={
                        "q": f"{searchTerm} fork:true in:name,description,topics,readme",
                        "per_page": 100,
                        "page": 1
                    }
                )
                isStartingFromPage2 = True
            # Make next request to get next batch of data and pagination information
            else:
                if nextUrl not in [None, ""]:
                    response = session.get(
                        url=nextUrl
                    )
                else:
                    break
        except Exception as e:
            printError(f"[!] Request for repositories matching search term '{searchTerm}' failed; error: {e}")
            break
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""

        # Process current batch of data
        if response.ok:
            try:
                responseJson = response.json()
                items = responseJson["items"]
            except Exception as e:
                printError(f"[!] Could not parse repositories response for search term '{searchTerm}'; error: {e}")
                break
            allItems.extend(items)
        else:
            printError(f"[!] Failed to get repositories matching search term '{searchTerm}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def searchForUser(name=""):
    # Exact lookup; /users/{name} works for both users and organisations and never fuzzy-matches a wrong account
    try:
        response = session.get(
            url=f"https://api.github.com/users/{name}"
        )
    except Exception as e:
        printError(f"[!] Failed to look up user/organisation '{name}'; error: {e}")
        return None
    if response.ok:
        try:
            return response.json()
        except Exception as e:
            printError(f"[!] Could not parse lookup response for user/organisation '{name}'; error: {e}")
            return None
    else:
        printError(f"[!] Failed to look up user/organisation '{name}'; HTTP {response.status_code}")
        return None

def getCommits(repoFullname="", userOrOrgName=""):
    # Get commits of a Repo
    if repoFullname != "":
        startUrl = f"https://api.github.com/repos/{repoFullname}/commits"
        isStartingFromPage2 = False
        nextUrl = ""
        allItems = []

        while True:
            # Make first request to get first batch of data and pagination information
            try:
                if not isStartingFromPage2:
                    response = session.get(
                        url=startUrl,
                        params={
                            "per_page": 100,
                            "page": 1
                        }
                    )
                    isStartingFromPage2 = True
                # Make next request to get next batch of data and pagination information
                else:
                    if nextUrl not in [None, ""]:
                        response = session.get(
                            url=nextUrl
                        )
                    else:
                        break
            except Exception as e:
                printError(f"[!] Request for commits of repository '{repoFullname}' failed; error: {e}")
                break
            # Save next URL for next batch of processing
            try:
                nextUrl = response.links["next"]["url"]
            except KeyError:
                nextUrl = ""

            # Process current batch of data
            if response.ok:
                try:
                    responseJson = response.json()
                except Exception as e:
                    printError(f"[!] Could not parse commits response for repository '{repoFullname}'; error: {e}")
                    break
                allItems.extend(responseJson)
            else:
                printError(f"[!] Failed to get commits of repository '{repoFullname}'; HTTP {response.status_code}; moving on with results gathered so far")
                break

        # Get the actual commit itself
        for i in range (0, len(allItems)):
            try:
                response = session.get(
                    url=allItems[i]["url"]
                )
                responseJson = response.json()
                allItems[i]["commitDetails"] = responseJson
            except Exception as e:
                printError(f"[!] Failed to get details of a commit in repository '{repoFullname}'; error: {e}")
                allItems[i]["commitDetails"] = {"files": []}

        return allItems

    # Get commits of a user/org
    else:
        allItems = []

        isStartingFromPage2 = False
        nextUrl = ""
        while True:
            # Make first request to get first batch of data and pagination information
            try:
                if not isStartingFromPage2:
                    response = session.get(
                        url="https://api.github.com/search/commits",
                        params={
                            "q": f"author:{userOrOrgName}",
                            "per_page": 100,
                            "page": 1
                        }
                    )
                    isStartingFromPage2 = True
                # Make next request to get next batch of data and pagination information
                else:
                    if nextUrl not in [None, ""]:
                        response = session.get(
                            url=nextUrl
                        )
                    else:
                        break
            except Exception as e:
                printError(f"[!] Request for commits authored by '{userOrOrgName}' failed; error: {e}")
                break
            # Save next URL for next batch of processing
            try:
                nextUrl = response.links["next"]["url"]
            except KeyError:
                nextUrl = ""

            # Process current batch of data
            if response.ok:
                try:
                    responseJson = response.json()
                    items = responseJson["items"]
                except Exception as e:
                    printError(f"[!] Could not parse commits response for author '{userOrOrgName}'; error: {e}")
                    break
                allItems.extend(items)
            else:
                printError(f"[!] Failed to get commits authored by '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
                break

        isStartingFromPage2 = False
        nextUrl = ""
        while True:
            # Make first request to get first batch of data and pagination information
            try:
                if not isStartingFromPage2:
                    response = session.get(
                        url="https://api.github.com/search/commits",
                        params={
                            "q": f"committer:{userOrOrgName}",
                            "per_page": 100,
                            "page": 1
                        }
                    )
                    isStartingFromPage2 = True
                # Make next request to get next batch of data and pagination information
                else:
                    if nextUrl not in [None, ""]:
                        response = session.get(
                            url=nextUrl
                        )
                    else:
                        break
            except Exception as e:
                printError(f"[!] Request for commits committed by '{userOrOrgName}' failed; error: {e}")
                break
            # Save next URL for next batch of processing
            try:
                nextUrl = response.links["next"]["url"]
            except KeyError:
                nextUrl = ""

            # Process current batch of data
            if response.ok:
                try:
                    responseJson = response.json()
                    items = responseJson["items"]
                except Exception as e:
                    printError(f"[!] Could not parse commits response for committer '{userOrOrgName}'; error: {e}")
                    break
                allItems.extend(items)
            else:
                printError(f"[!] Failed to get commits committed by '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
                break

        # Same commit can appear in both author and committer search results; dedupe before fetching details
        seenCommitShas = set()
        dedupedItems = []
        for item in allItems:
            if item["sha"] not in seenCommitShas:
                seenCommitShas.add(item["sha"])
                dedupedItems.append(item)
        allItems = dedupedItems

        # Get the actual commit itself
        for i in range (0, len(allItems)):
            try:
                response = session.get(
                    url=allItems[i]["url"]
                )
                responseJson = response.json()
                allItems[i]["commitDetails"] = responseJson
            except Exception as e:
                printError(f"[!] Failed to get details of a commit by '{userOrOrgName}'; error: {e}")
                allItems[i]["commitDetails"] = {"files": []}

        return allItems


# Main function
def gather(outputDir, githubPatToken="", searchTerms=[], knownUsers=[], knownOrgs=[], maxSearchDepth=1, noColor=False):
    # TODO: https://github.com/trufflesecurity/trufflehog/releases

    # Token comes from main.py (which loads all env vars); without it nothing can be gathered
    if githubPatToken in [None, ""]:
        raise Exception("GitHub PAT Token not found. Check your .env.")
    setupGithubSessions(githubPatToken)
    setupOutputFormatting(noColor)

    # Persistent data
    repositoriesToSearchIn = [] # [{  }]
    linkedUsersOrOrgs = []
    userOrOrgGistsToSearchIn = []
    userOrOrgCommitsToSearchIn = []

    # Prepare directory for output
    try:
        mkdir(outputDir)
    except:
        pass

    try:
        logOutputFilePath = path.join(outputDir, "output.log")
        resultsOutputFilePath = path.join(outputDir, "results.txt")

        logOutputFile = open(logOutputFilePath, "a")
        resultsOutputFile = open(resultsOutputFilePath, "a")

        print(f"[+] Project output directory '{outputDir}' set up; all logs and outputs would be there")
    except Exception as e:
        # Without the output directory nothing can be saved, so exit altogether
        printError(f"[!] Failed to prepare output directory '{outputDir}'; error: {e}")
        sys.exit(1)

    def logText(text: str, level: int = 0, kind: str = "info"):
        # Blank text = blank line in both STDOUT and the log file (spacing between groups)
        if text == "":
            print()
            logOutputFile.write("\n")
            logOutputFile.flush()
            return

        # STDOUT gets indentation and colours; the log file gets the same lines plain (tabs, no colour)
        markers = {"stage": "[>]", "info": "[.]", "success": "[+]", "error": "[!]"}
        colours = {
            "stage": ANSI_BOLD + ANSI_CYAN,
            "info": ANSI_BLUE,
            "success": ANSI_GREEN,
            "error": ANSI_RED
        }
        marker = markers.get(kind, "[.]")
        indent = "\t" * level
        plainLine = f"{indent}{marker} {text}"
        if useColor:
            print(f"{indent}{colours.get(kind, "")}{marker}{ANSI_RESET} {text}")
        else:
            print(plainLine)
        logOutputFile.write(plainLine + "\n")
        logOutputFile.flush()

    logText(f"Project directory: '{outputDir}'", kind="stage")

    # Find all Depth=1 target repositories
    knownUsersDetailed = []
    knownOrgsDetailed = []
    for knownUser in knownUsers:
        knownUserDetails = searchForUser(name=knownUser)
        if knownUserDetails != None:
            knownUserDetails["evidenceChain"] = ["Directly mentioned by user"]
            knownUsersDetailed.append(knownUserDetails)
    for knownOrg in knownOrgs:
        knownOrgDetails = searchForUser(name=knownOrg)
        if knownOrgDetails != None:
            knownOrgDetails["evidenceChain"] = ["Directly mentioned by user"]
            knownOrgsDetailed.append(knownOrgDetails)
    knownUsers = knownUsersDetailed
    knownOrgs = knownOrgsDetailed


    logText("")
    logText("Finding repositories owned by known users/organisations...", kind="stage")
    for knownUser in knownUsers:
        logText(f"Finding repositories owned by user '{knownUser["login"]}'...", level=1)

        repositories = getReposOwnedByUserOrOrg(
            userOrOrgName=knownUser["login"],
            isUser=True
        )

        repositoriesToSearchIn.extend(repositories)

        logText(f"{len(repositories)} repositories found", level=2, kind="success")
    for knownOrg in knownOrgs:
        logText(f"Finding repositories owned by organisation '{knownOrg["login"]}'...", level=1)

        repositories = getReposOwnedByUserOrOrg(
            userOrOrgName=knownOrg["login"],
            isUser=False
        )
        repositoriesToSearchIn.extend(repositories)

        logText(f"{len(repositories)} repositories found", level=2, kind="success")

    # Find repositories matching each given search term; add them deduped, so that
    # all already-existing code later picks them up just like user/org-owned repositories
    seenRepositoryFullNames = set(map(lambda x: x["full_name"], repositoriesToSearchIn))
    if len(searchTerms) > 0:
        logText("")
        logText("Finding repositories matching given search terms...", kind="stage")
    for searchTerm in searchTerms:
        repositories = []

        # Use search term in readme, title, description, etc
        logText(f"Finding repositories matching search term '{searchTerm}' in title, readme, description, etc...", level=1)
        repositories.extend(getReposFromNameSearchTerm(searchTerm=searchTerm))

        # Use search term in code
        logText(f"Finding repositories matching search term '{searchTerm}' in code...", level=1)
        resultsFromCodeSearch = getReposFromCodeSearch(searchTerm=searchTerm)
        for i in range(0, len(resultsFromCodeSearch)):
            repoFullName = resultsFromCodeSearch[i]["repository"]["full_name"]
            filePath = resultsFromCodeSearch[i]["path"]
            htmlUrl = resultsFromCodeSearch[i]["html_url"]
            sha = resultsFromCodeSearch[i]["sha"]
            textMatches = resultsFromCodeSearch[i]["text_matches"]

            resultsFromCodeSearch[i]["evidenceChain"] = [
                f"{len(textMatches)} match(s) found for code search term '{searchTerm}' in repo '{repoFullName}', file '{filePath}'({sha})"
            ]

            repositories.append(resultsFromCodeSearch[i]["repository"])

        logText(f"Code search found {len(resultsFromCodeSearch)} matches across repositories.", level=1, kind="success")

        newRepositoriesCount = 0
        for repository in repositories:
            if repository["full_name"] not in seenRepositoryFullNames:
                repository["evidenceChain"] = [
                    f"Found from search term '{searchTerm}'"
                ]
                repositoriesToSearchIn.append(repository)
                seenRepositoryFullNames.add(repository["full_name"])
                newRepositoriesCount += 1

        logText(f"{newRepositoriesCount} new repositories found ({len(repositories) - newRepositoriesCount} already known)", level=2, kind="success")

    for i in range(0, len(repositoriesToSearchIn)):
        # Repositories found via search terms already have their evidence chain; don't overwrite it
        if "evidenceChain" not in repositoriesToSearchIn[i]:
            repositoriesToSearchIn[i]["evidenceChain"] = ["Directly mentioned by user"]
        repositoriesToSearchIn[i]["useForFurtherSearchDepth"] = 2

    # Set for fast membership checks (rebuilding lists on every check is O(n^2) on big targets)
    seenUserOrOrgLogins = set(map(lambda x: x["login"], knownUsers + knownOrgs))

    # Follow search depth, and gather more target repositories
    if maxSearchDepth != 1:
        logText("")
        logText("Finding contributors to above found repositories, then other repositories owned by them...", kind="stage")

    searchDepth = 2
    while searchDepth <= maxSearchDepth:

        # Loop through all repositories
        for repositoryToSearchIn in repositoriesToSearchIn:
            # Only if repository was not already processed before
            if repositoryToSearchIn["useForFurtherSearchDepth"] == searchDepth:

                # Find contributors to already-found repositories
                logText(f"Search depth {searchDepth} | Repository '{repositoryToSearchIn["full_name"]}': finding contributors and forks...", level=1)

                contributors = getContributorsOfARepository(
                    contributorsUrl=repositoryToSearchIn["contributors_url"]
                )
                for contributor in contributors:
                    if contributor["login"] not in seenUserOrOrgLogins:
                        contributor["evidenceChain"] = [
                            f"Found contributor to repository '{repositoryToSearchIn["full_name"]}'"
                        ]
                        contributor["useForFurtherSearchDepth"] = searchDepth
                        linkedUsersOrOrgs.append(contributor)
                        seenUserOrOrgLogins.add(contributor["login"])

                logText(f"{len(contributors)} contributors found", level=2, kind="success")

                # Find forks of existing repositories
                forks = getForks(repoFullName=repositoryToSearchIn["full_name"])
                for fork in forks:
                    if fork["full_name"] not in seenRepositoryFullNames:
                        fork["evidenceChain"] = [
                            f"Found fork '{fork["full_name"]}' of discovered repository '{repositoryToSearchIn["full_name"]}'"
                        ]
                        fork["useForFurtherSearchDepth"] = searchDepth + 1
                        repositoriesToSearchIn.append(fork)
                        seenRepositoryFullNames.add(fork["full_name"])
                logText(f"{len(forks)} forks found", level=2, kind="success")



        # Make set of repositories to process
        for userOrOrg in linkedUsersOrOrgs:
            # Only if user/org was not already processed before
            if userOrOrg["useForFurtherSearchDepth"] == searchDepth:
                logText(f"Search depth {searchDepth} | Finding repositories owned by {userOrOrg["type"].lower()} '{userOrOrg["login"]}'...", level=1)

                repositories = getReposOwnedByUserOrOrg(
                    userOrOrgName=userOrOrg["login"],
                    isUser=userOrOrg["type"].lower() == "user"
                )
                for repository in repositories:
                    if repository["full_name"] not in seenRepositoryFullNames:
                        repository["evidenceChain"] = [
                            f"Found linked to {userOrOrg["type"].lower()} '{userOrOrg["login"]}', who is a contributor with evidence chain: {userOrOrg["evidenceChain"]}"
                            ]
                        repository["useForFurtherSearchDepth"] = searchDepth + 1
                        repositoriesToSearchIn.append(repository)
                        seenRepositoryFullNames.add(repository["full_name"])

                logText(f"{len(repositories)} repositories found", level=2, kind="success")

        # Increase search depth by 1 because all processing is done
        searchDepth += 1

    # Process all users (knownUsers + knownOrgs + linkedUsersOrOrgs): commits, gists
    logText("")
    logText("Finding all commits and gists by all given and found users and organsations...", kind="stage")

    for userOrOrg in knownUsers + knownOrgs:
        logText(f"Provided user/organisation '{userOrOrg["login"]}': finding commits and gists...", level=1)
        response = getCommits(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was provided by user"
            ]
        userOrOrgCommitsToSearchIn.extend(response)
        logText(f"{len(response)} commits found", level=2, kind="success")

        response = getGists(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was provided by user"
            ]
        userOrOrgGistsToSearchIn.extend(response)
        logText(f"{len(response)} gists found", level=2, kind="success")

    for userOrOrg in linkedUsersOrOrgs:
        logText(f"Discovered user/organisation '{userOrOrg["login"]}': finding commits and gists...", level=1)
        response = getCommits(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was found linked to a discovered repository. User/org's evidence chain: {userOrOrg["evidenceChain"]}"
            ]
        userOrOrgCommitsToSearchIn.extend(response)
        logText(f"{len(response)} commits found", level=2, kind="success")

        response = getGists(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was found linked to a discovered repository. User/org's evidence chain: {userOrOrg["evidenceChain"]}"
            ]
        userOrOrgGistsToSearchIn.extend(response)

        logText(f"{len(response)} gists found", level=2, kind="success")

    # Process all repos: commits, commit comments, issues, issue comments and PRs
    logText("")
    logText("Processing all commits, commit comments, issues, issue comments and PRs of each found repository...", kind="stage")

    for i in range(0, len(repositoriesToSearchIn)):
        logText(f"Repository '{repositoriesToSearchIn[i]["full_name"]}': finding commits, commit comments, issues, issue comments and PRs...", level=1)

        # All commits of the repository
        commits = getCommits(repoFullname=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(commits)):
            commits[j]["evidenceChain"] = [
                f"Commit from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["allCommits"] = commits
        logText(f"{len(commits)} commits found", level=2, kind="success")

        # All commit comments of the repository
        commitComments = getCommitComments(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(commitComments)):
            commitComments[j]["evidenceChain"] = [
                f"Comment in commit {commitComments[j]["commit_id"]} in repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["commitComments"] = commitComments
        logText(f"{len(commitComments)} commit comments found", level=2, kind="success")

        # All issues of the repository
        issues = getIssues(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(issues)):
            issues[j]["evidenceChain"] = [
                f"Issue from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["issues"] = issues
        logText(f"{len(issues)} issues found", level=2, kind="success")

        # All issue comments of the repository
        issueComments = getIssueComments(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(issueComments)):
            issueComments[j]["evidenceChain"] = [
                f"Comment in issue '{issueComments[j]["html_url"]}' in repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["issueComments"] = issueComments
        logText(f"{len(issueComments)} issue comments found", level=2, kind="success")

        # All PRs of the repository
        pullRequests = getPullRequests(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(pullRequests)):
            pullRequests[j]["evidenceChain"] = [
                f"PR {pullRequests[j]["number"]} from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["pullRequests"] = pullRequests
        logText(f"{len(pullRequests)} PRs found", level=2, kind="success")

    # Download the actual data into proper directories
    logText("")
    logText(f"Saving all data at '{outputDir}'...", kind="stage")

    saveGists(
            projectDirPath=outputDir,
            gistsList=userOrOrgGistsToSearchIn
        )
    logText("Saved all gists", level=1, kind="success")

    saveCommits(
        repoSaveDirPath=outputDir,
        commitsList=userOrOrgCommitsToSearchIn
    )
    logText("Saved all commits mapped from users/orgs", level=1, kind="success")

    saveCode(
        repoSaveDirPath=outputDir,
        resultsFromCodeSearch=resultsFromCodeSearch
    )
    logText("Saved all code search results", level=1, kind="success")

    allReposPath = path.join(outputDir, "repos")
    try:
        mkdir(allReposPath)
    except FileExistsError:
        pass
    except Exception as e:
        logText(f"Could not create directory '{allReposPath}'; error: {e}", level=1, kind="error")
    for repositoryToSearchIn in repositoriesToSearchIn:
        repoPath = path.join(allReposPath, repositoryToSearchIn["full_name"].replace("/", "__"))
        try:
            mkdir(repoPath)
        except FileExistsError:
            pass
        except Exception as e:
            logText(f"Could not create directory '{repoPath}'; error: {e}", level=1, kind="error")
            continue

        logText(f"Repository '{repositoryToSearchIn["full_name"]}':", level=1)
        saveCommits(
            repoSaveDirPath=repoPath,
            commitsList=repositoryToSearchIn["allCommits"]
        )
        saveCommitComments(
            repoSaveDirPath=repoPath,
            commitCommentsList=repositoryToSearchIn["commitComments"]
        )
        saveIssues(
            repoSaveDirPath=repoPath,
            issuesList=repositoryToSearchIn["issues"]
        )
        saveIssueComments(
            repoSaveDirPath=repoPath,
            issueCommentsList=repositoryToSearchIn["issueComments"]
        )
        savePullRequests(
            repoSaveDirPath=repoPath,
            pullRequestsList=repositoryToSearchIn["pullRequests"]
        )
        logText("Saved all extracted intel", level=2, kind="success")

        stdout, stderr, returncode = cloneRepository(
            gitRepositoryCloneUrl=repositoryToSearchIn["clone_url"],
            gitRepositorySavePath=path.join(repoPath, repositoryToSearchIn["name"])
        )
        if returncode == 0:
            logText("Cloned", level=2, kind="success")
        else:
            # Sanitise stderr just in case git echoes the credential back
            logText(f"Failed to clone; error: {stderr.replace(githubPatToken, "***").strip()}", level=2, kind="error")

    # Run trufflehog
    runTrufflehog(
        logText=logText,
        outputDir=outputDir,
        repositoriesToSearchIn=repositoriesToSearchIn
    )

    # Close open files
    logOutputFile.close()
    resultsOutputFile.close() #TODO write results
