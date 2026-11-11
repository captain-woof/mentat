from requests import Session
from requests_ratelimiter import LimiterAdapter
from os import mkdir, path
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
        logText("[!] 'trufflehog' binary not found in PATH; skipping all trufflehog scans")
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
        logText(f"[!] Could not create directory '{trufflehogTempDir}'; error: {e}")
    try:
        mkdir(trufflehogDir)
    except FileExistsError:
        pass
    except Exception as e:
        logText(f"[!] Could not create directory '{trufflehogDir}'; error: {e}")

    logText(f"[.] Running Trufflehog on all repositories...")

    # Run in Local Git mode
    for repositoryToSearchIn in repositoriesToSearchIn:
        gitDir = path.join(outputDir, "repos", repositoryToSearchIn["full_name"].replace("/", "__"), repositoryToSearchIn["name"])

        # Repo may not have been cloned (e.g. private repo without access); skip instead of scanning nothing
        if not path.exists(gitDir):
            logText(f"\t[!] Skipping trufflehog git scan for '{repositoryToSearchIn["full_name"]}': no local clone at '{gitDir}'")
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
            logText(f"\t[!] Failed to run trufflehog on repo '{repositoryToSearchIn["full_name"]}'; error: {e}")
            continue

        with open(trufflehogRepoResultsJsonPath, "a") as trufflehogRepoResultsFile:
            trufflehogRepoResultsFile.write(stdout)
            trufflehogRepoResultsFile.flush()

        findingsCount = makeHumanReadableTrufflehogReport(
            jsonResultsPath=trufflehogRepoResultsJsonPath,
            reportPath=trufflehogRepoResultsReportPath,
            stderrText=stderr
        )

        logText(f"\t[+] Ran trufflehog on repo {repositoryToSearchIn["full_name"]} ({findingsCount} findings); results in '{trufflehogRepoResultsJsonPath}'")

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
        logText(f"\t[!] Failed to run trufflehog in filesystem mode; error: {e}")
        stdout, stderr = "", ""

    with open(trufflehogFilesystemResultsJsonPath, "a") as trufflehogFilesystemResultsFile:
        trufflehogFilesystemResultsFile.write(stdout)
        trufflehogFilesystemResultsFile.flush()

    findingsCount = makeHumanReadableTrufflehogReport(
        jsonResultsPath=trufflehogFilesystemResultsJsonPath,
        reportPath=trufflehogFilesystemResultsReportPath,
        stderrText=stderr
    )

    logText(f"\t[+] Ran trufflehog on all text results ({findingsCount} findings); output in '{trufflehogFilesystemResultsJsonPath}'")

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
        logText(f"\t[+] Moved all trufflehog results to '{trufflehogFinalDir}'")
    except Exception as e:
        logText(f"\t[!] Failed to move trufflehog results into '{outputDir}'; results left at '{trufflehogDir}'; error: {e}")

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
        print(f"[!] Failed to run git clone for '{gitRepositoryCloneUrl}'; error: {e}")
        return ("", str(e), 1)

    if p.returncode != 0:
        print(f"[!] Failed to clone '{gitRepositoryCloneUrl}'; error: {stderr.strip()}")

    return (stdout, stderr, p.returncode)

def saveGists(projectDirPath, gistsList = []):
    gistsPath = path.join(projectDirPath, "gists")
    try:
        mkdir(gistsPath)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"[!] Could not create directory '{gistsPath}'; error: {e}")

    for gist in gistsList:
        try:
            gistDetails = gist.get("gistDetails", {})
            if gistDetails == {}:
                print(f"[!] Skipping a gist: no details were downloaded")
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
            print(f"[!] Failed to save a gist; error: {e}")

def savePullRequests(repoSaveDirPath, pullRequestsList = []):
    pullRequestsPath = path.join(repoSaveDirPath, "PRs")
    try:
        mkdir(pullRequestsPath)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"[!] Could not create directory '{pullRequestsPath}'; error: {e}")

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
            print(f"[!] Failed to save a PR; error: {e}")


def saveCommits(repoSaveDirPath, commitsList = []):
    commitsPath = path.join(repoSaveDirPath, "commits")
    try:
        mkdir(commitsPath)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"[!] Could not create directory '{commitsPath}'; error: {e}")

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
            print(f"[!] Failed to save a commit; error: {e}")

def saveCommitComments(repoSaveDirPath, commitCommentsList = []):
    commitCommentsPath = path.join(repoSaveDirPath, "commit-comments")
    try:
        mkdir(commitCommentsPath)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"[!] Could not create directory '{commitCommentsPath}'; error: {e}")

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
            print(f"[!] Failed to save a commit comment; error: {e}")

def saveIssues(repoSaveDirPath, issuesList = []):
    issuesPath = path.join(repoSaveDirPath, "issues")
    try:
        mkdir(issuesPath)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"[!] Could not create directory '{issuesPath}'; error: {e}")

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
            print(f"[!] Failed to save an issue; error: {e}")

def saveIssueComments(repoSaveDirPath, issueCommentsList = []):
    issueComments = path.join(repoSaveDirPath, "issue-comments")
    try:
        mkdir(issueComments)
    except FileExistsError:
        pass
    except Exception as e:
        print(f"[!] Could not create directory '{issueComments}'; error: {e}")

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
            print(f"[!] Failed to save an issue comment; error: {e}")

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
            print(f"[!] Request for PRs of repository '{repoFullName}' failed; error: {e}")
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
                print(f"[!] Could not parse PRs response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            print(f"[!] Failed to get PRs of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
            print(f"[!] Failed to get patch details of a PR in repository '{repoFullName}'; error: {e}")
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
            print(f"[!] Request for issues of repository '{repoFullName}' failed; error: {e}")
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
                print(f"[!] Could not parse issues response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            print(f"[!] Failed to get issues of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
            print(f"[!] Request for issue comments of repository '{repoFullName}' failed; error: {e}")
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
                print(f"[!] Could not parse issue comments response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            print(f"[!] Failed to get issue comments of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
            print(f"[!] Request for commit comments of repository '{repoFullName}' failed; error: {e}")
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
                print(f"[!] Could not parse commit comments response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            print(f"[!] Failed to get commit comments of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
            print(f"[!] Request for forks of repository '{repoFullName}' failed; error: {e}")
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
                print(f"[!] Could not parse forks response for repository '{repoFullName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            print(f"[!] Failed to get forks of repository '{repoFullName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
            print(f"[!] Request for gists of user/organisation '{userOrOrgName}' failed; error: {e}")
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
                print(f"[!] Could not parse gists response for user/organisation '{userOrOrgName}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            print(f"[!] Failed to get gists of user/organisation '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
            print(f"[!] Failed to get details of a gist of user/organisation '{userOrOrgName}'; error: {e}")
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
            print(f"[!] Request for contributors '{contributorsUrl}' failed; error: {e}")
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
                print(f"[!] Could not parse contributors response '{contributorsUrl}'; error: {e}")
                break
            allItems.extend(responseJson)
        else:
            print(f"[!] Failed to get contributors '{contributorsUrl}'; HTTP {response.status_code}; moving on with results gathered so far")
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
            print(f"[!] Request for repositories owned by '{userOrOrgName}' failed; error: {e}")
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
                print(f"[!] Could not parse repositories response for '{userOrOrgName}'; error: {e}")
                break
            allItems.extend(items)
        else:
            print(f"[!] Failed to get repositories owned by '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
            break
    return allItems

def searchForUser(name=""):
    # Exact lookup; /users/{name} works for both users and organisations and never fuzzy-matches a wrong account
    try:
        response = session.get(
            url=f"https://api.github.com/users/{name}"
        )
    except Exception as e:
        print(f"[!] Failed to look up user/organisation '{name}'; error: {e}")
        return None
    if response.ok:
        try:
            return response.json()
        except Exception as e:
            print(f"[!] Could not parse lookup response for user/organisation '{name}'; error: {e}")
            return None
    else:
        print(f"[!] Failed to look up user/organisation '{name}'; HTTP {response.status_code}")
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
                print(f"[!] Request for commits of repository '{repoFullname}' failed; error: {e}")
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
                    print(f"[!] Could not parse commits response for repository '{repoFullname}'; error: {e}")
                    break
                allItems.extend(responseJson)
            else:
                print(f"[!] Failed to get commits of repository '{repoFullname}'; HTTP {response.status_code}; moving on with results gathered so far")
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
                print(f"[!] Failed to get details of a commit in repository '{repoFullname}'; error: {e}")
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
                print(f"[!] Request for commits authored by '{userOrOrgName}' failed; error: {e}")
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
                    print(f"[!] Could not parse commits response for author '{userOrOrgName}'; error: {e}")
                    break
                allItems.extend(items)
            else:
                print(f"[!] Failed to get commits authored by '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
                print(f"[!] Request for commits committed by '{userOrOrgName}' failed; error: {e}")
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
                    print(f"[!] Could not parse commits response for committer '{userOrOrgName}'; error: {e}")
                    break
                allItems.extend(items)
            else:
                print(f"[!] Failed to get commits committed by '{userOrOrgName}'; HTTP {response.status_code}; moving on with results gathered so far")
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
                print(f"[!] Failed to get details of a commit by '{userOrOrgName}'; error: {e}")
                allItems[i]["commitDetails"] = {"files": []}

        return allItems


# Main function
def gather(outputDir, githubPatToken="", searchTerms=[], knownUsers=[], knownOrgs=[], maxSearchDepth=1):
    # TODO: https://github.com/trufflesecurity/trufflehog/releases

    # Token comes from main.py (which loads all env vars); without it nothing can be gathered
    if githubPatToken in [None, ""]:
        raise Exception("GitHub PAT Token not found. Check your .env.")
    setupGithubSessions(githubPatToken)

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
        print(f"[!] Failed to prepare output directory '{outputDir}'; error: {e}")
        sys.exit(1)

    def logText(text: str):
        print(text)
        logOutputFile.write(text + "\n")
        logOutputFile.flush()

    logText(f"[>] Project directory: '{outputDir}'")

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


    for knownUser in knownUsers:
        logText(f"[.] Finding repositories owned by user '{knownUser["login"]}'...")

        repositories = getReposOwnedByUserOrOrg(
            userOrOrgName=knownUser["login"],
            isUser=True
        )

        repositoriesToSearchIn.extend(repositories)

        logText(f"[+] {len(repositories)} repositories found owned by user '{knownUser["login"]}'")
    for knownOrg in knownOrgs:
        logText(f"[.] Finding repositories owned by organisation '{knownOrg["login"]}'...")

        repositories = getReposOwnedByUserOrOrg(
            userOrOrgName=knownOrg["login"],
            isUser=False
        )
        repositoriesToSearchIn.extend(repositories)

        logText(f"[+] {len(repositories)} repositories found owned by organisation '{knownOrg["login"]}'")

    for i in range(0, len(repositoriesToSearchIn)):
        repositoriesToSearchIn[i]["evidenceChain"] = ["Directly mentioned by user"]
        repositoriesToSearchIn[i]["useForFurtherSearchDepth"] = 2

    # Sets for fast membership checks (rebuilding lists on every check is O(n^2) on big targets)
    seenRepositoryFullNames = set(map(lambda x: x["full_name"], repositoriesToSearchIn))
    seenUserOrOrgLogins = set(map(lambda x: x["login"], knownUsers + knownOrgs))

    # Follow search depth, and gather more target repositories
    if maxSearchDepth != 1:
        logText("[.] Finding contributors to above found repositories, then other repositories owned by them...")

    searchDepth = 2
    while searchDepth <= maxSearchDepth:

        # Loop through all repositories
        for repositoryToSearchIn in repositoriesToSearchIn:
            # Only if repository was not already processed before
            if repositoryToSearchIn["useForFurtherSearchDepth"] == searchDepth:

                # Find contributors to already-found repositories
                logText(f"[.] Search depth: {searchDepth}; finding contributors to repository '{repositoryToSearchIn["full_name"]}'")

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

                logText(f"[+] Search depth: {searchDepth}; found {len(contributors)} contributors to repository '{repositoryToSearchIn["full_name"]}'")

                # Find forks of existing repositories
                logText(f"[.] Search depth: {searchDepth}; finding forks of repository '{repositoryToSearchIn["full_name"]}'")
                forks = getForks(repoFullName=repositoryToSearchIn["full_name"])
                for fork in forks:
                    if fork["full_name"] not in seenRepositoryFullNames:
                        fork["evidenceChain"] = [
                            f"Found fork '{fork["full_name"]}' of discovered repository '{repositoryToSearchIn["full_name"]}'"
                        ]
                        fork["useForFurtherSearchDepth"] = searchDepth + 1
                        repositoriesToSearchIn.append(fork)
                        seenRepositoryFullNames.add(fork["full_name"])
                logText(f"[+] Search depth: {searchDepth}; found {len(forks)} forks to repository '{repositoryToSearchIn["full_name"]}'")



        # Make set of repositories to process
        for userOrOrg in linkedUsersOrOrgs:
            # Only if user/org was not already processed before
            if userOrOrg["useForFurtherSearchDepth"] == searchDepth:
                logText(f"[.] Search depth: {searchDepth}; finding repositories owned by {userOrOrg["type"].lower()} '{userOrOrg["login"]}'")

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

                logText(f"[+] Search depth: {searchDepth}; found {len(repositories)} repositories owned by {userOrOrg["type"].lower()} '{userOrOrg["login"]}'")

        # Increase search depth by 1 because all processing is done
        searchDepth += 1

    # Process all users (knownUsers + knownOrgs + linkedUsersOrOrgs): commits, gists
    logText("[.] Finding all commits and gists by all given and found users and organsations...")

    for userOrOrg in knownUsers + knownOrgs:
        response = getCommits(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was provided by user"
            ]
        userOrOrgCommitsToSearchIn.extend(response)
        logText(f"[+] Found {len(response)} commits by given user/organisation '{userOrOrg["login"]}'")

        response = getGists(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was provided by user"
            ]
        userOrOrgGistsToSearchIn.extend(response)
        logText(f"\t[+] found {len(response)} gists by provided user/organisation '{userOrOrg["login"]}'")

    for userOrOrg in linkedUsersOrOrgs:
        response = getCommits(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was found linked to a discovered repository. User/org's evidence chain: {userOrOrg["evidenceChain"]}"
            ]
        userOrOrgCommitsToSearchIn.extend(response)
        logText(f"[+] Found {len(response)} commits by discovered user/organisation '{userOrOrg["login"]}'")

        response = getGists(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was found linked to a discovered repository. User/org's evidence chain: {userOrOrg["evidenceChain"]}"
            ]
        userOrOrgGistsToSearchIn.extend(response)

        logText(f"\t[+] found {len(response)} gists by discovered user/organisation '{userOrOrg["login"]}'")

    # Process all repos: commits, commit comments, issues, issue comments and PRs
    logText("[.] Processing all commits, commit comments, issues, issue comments and PRs of each found repository...")

    for i in range(0, len(repositoriesToSearchIn)):
        # All commits of the repository
        logText(f"\t[.] Finding all commits in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        commits = getCommits(repoFullname=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(commits)):
            commits[j]["evidenceChain"] = [
                f"Commit from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["allCommits"] = commits
        logText(f"\t[+] Found {len(commits)} commits in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All commit comments of the repository
        logText(f"\t[.] Finding all commit comments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        commitComments = getCommitComments(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(commitComments)):
            commitComments[j]["evidenceChain"] = [
                f"Comment in commit {commitComments[j]["commit_id"]} in repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["commitComments"] = commitComments
        logText(f"\t[+] Found {len(commitComments)} commit comments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All issues of the repository
        logText(f"\t[.] Finding all issues in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        issues = getIssues(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(issues)):
            issues[j]["evidenceChain"] = [
                f"Issue from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["issues"] = issues
        logText(f"\t[+] Found {len(issues)} issues in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All issue comments of the repository
        logText(f"\t[.] Finding all issue comments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        issueComments = getIssueComments(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(issueComments)):
            issueComments[j]["evidenceChain"] = [
                f"Comment in issue '{issueComments[j]["html_url"]}' in repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["issueComments"] = issueComments
        logText(f"\t[+] Found {len(issueComments)} issueComments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All PRs of the repository
        logText(f"\t[.] Finding all PRs in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        pullRequests = getPullRequests(repoFullName=repositoriesToSearchIn[i]["full_name"])
        for j in range(0, len(pullRequests)):
            pullRequests[j]["evidenceChain"] = [
                f"PR {pullRequests[j]["number"]} from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["pullRequests"] = pullRequests
        logText(f"\t[+] Found {len(pullRequests)} PRs in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

    # Download the actual data into proper directories
    logText(f"[.] Saving all data at '{outputDir}'...")

    saveGists(
            projectDirPath=outputDir,
            gistsList=userOrOrgGistsToSearchIn
        )
    logText(f"\t [+] Saved all gists")

    saveCommits(
        repoSaveDirPath=outputDir,
        commitsList=userOrOrgCommitsToSearchIn
    )
    logText(f"\t [+] Saved all commits mapped from users/orgs")

    allReposPath = path.join(outputDir, "repos")
    try:
        mkdir(allReposPath)
    except FileExistsError:
        pass
    except Exception as e:
        logText(f"\t [!] Could not create directory '{allReposPath}'; error: {e}")
    for repositoryToSearchIn in repositoriesToSearchIn:
        repoPath = path.join(allReposPath, repositoryToSearchIn["full_name"].replace("/", "__"))
        try:
            mkdir(repoPath)
        except FileExistsError:
            pass
        except Exception as e:
            logText(f"\t [!] Could not create directory '{repoPath}'; error: {e}")
            continue

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
        logText(f"\t [+] Saved all extracted intel from repo '{repositoryToSearchIn["full_name"]}'")

        stdout, stderr, returncode = cloneRepository(
            gitRepositoryCloneUrl=repositoryToSearchIn["clone_url"],
            gitRepositorySavePath=path.join(repoPath, repositoryToSearchIn["name"])
        )
        if returncode == 0:
            logText(f"\t [+] Cloned repo '{repositoryToSearchIn["full_name"]}'")
        else:
            # Sanitise stderr just in case git echoes the credential back
            logText(f"\t [!] Failed to clone repo '{repositoryToSearchIn["full_name"]}'; error: {stderr.replace(githubPatToken, "***").strip()}")

    # Run trufflehog
    runTrufflehog(
        logText=logText,
        outputDir=outputDir,
        repositoriesToSearchIn=repositoriesToSearchIn
    )

    # Close open files
    logOutputFile.close()
    resultsOutputFile.close() #TODO write results
