from requests import Session
from requests_ratelimiter import LimiterAdapter
from os import environ, mkdir, path
import subprocess

# Create session object and configure for all web requests
githubPatToken = environ["GITHUB_PAT_TOKEN"]
if githubPatToken in [None, ""]:
    raise Exception("GitHub PAT Token not found. Check your .env.")

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
def runTrufflehog(outputDir, repositoriesToSearchIn, logText):
    # Create main dir
    trufflehogDir = path.join(outputDir, "trufflehog-results")
    mkdir(trufflehogDir)

    logText(f"[.] Running Trufflehog on all repositories...")

    # Run in Local Git mode
    for repositoryToSearchIn in repositoriesToSearchIn:
        gitDir = path.join(outputDir, "repos", repositoryToSearchIn["full_name"].replace("/", "__"), repositoryToSearchIn["name"])

        p = subprocess.Popen(
            args=[
                "trufflehog",
                "git",
                f"--config=rules-trufflehogv3.yml",
                f"file://{gitDir}"
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()

        trufflehogRepoResultsPath = path.join(trufflehogDir, f"{repositoryToSearchIn["full_name"].replace("/", "__")}.txt")
        with open(trufflehogRepoResultsPath, "a") as trufflehogRepoResultsFile:
            trufflehogRepoResultsFile.write(stdout + "\n" + stderr)
            trufflehogRepoResultsFile.flush()

        logText(f"\t[+] Ran trufflehog on repo {repositoryToSearchIn["full_name"]}; results in '{trufflehogRepoResultsPath}'")

    # Run in filesystem mode
    trufflehogFilesystemResultsPath = path.join(trufflehogDir, "results-from-all-filesystem-files-here.txt")
    p = subprocess.Popen(
        args=[
            "trufflehog",
            "filesystem",
            f"--config=rules-trufflehogv3.yml",
            outputDir
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = p.communicate()

    with open(trufflehogFilesystemResultsPath, "a") as trufflehogFilesystemResultsFile:
        trufflehogFilesystemResultsFile.write(stdout + "\n" + stderr)
        trufflehogFilesystemResultsFile.flush()

    logText(f"\t[+] Ran trufflehog on all text results; output in '{trufflehogRepoResultsPath}'")

def cloneRepository(gitRepositoryCloneUrl, gitRepositorySavePath):
    p = subprocess.Popen(
        args=[
            "git",
            "clone",
            gitRepositoryCloneUrl,
            gitRepositorySavePath
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    stdout, stderr = p.communicate()

    return (stdout, stderr)

def saveGists(projectDirPath, gistsList = []):
    gistsPath = path.join(projectDirPath, "gists")
    mkdir(gistsPath)

    for gist in gistsList:
        gistDetails = gist["gistDetails"]
        gistPath = path.join(gistsPath, f"{gistDetails["owner"]["login"]}_{gistDetails["id"]}.md")

        gistContents = f"""# Gist {gistDetails["id"]}

------------
# URL: {gistDetails["html_url"]}
------------
# EVIDENCE CHAIN:
{gist["evidenceChain"]}
------------
# CONTENTS:
------------
{"".join([f"{gistFileAndContent["filename"]}\n{gistFileAndContent["content"]}\n\n" for gistFileAndContent in gistDetails["files"].values()])}

"""
        with open(gistPath, "a") as gistFile:
            gistFile.write(gistContents)
            gistFile.flush()

def savePullRequests(repoSaveDirPath, pullRequestsList = []):
    pullRequestsPath = path.join(repoSaveDirPath, "PRs")
    mkdir(pullRequestsPath)

    for pullRequest in pullRequestsList:
        patchDetails = pullRequest["patchDetails"]

        pullRequestPath = path.join(pullRequestsPath, f"{pullRequest["user"]["login"]}_{pullRequest["id"]}")

        pullRequestContents = f"""# PR {pullRequest["id"]}

------------        
# URL: {pullRequest["html_url"]}
------------
# EVIDENCE CHAIN:
{pullRequest["evidenceChain"]}
------------
# BODY:
------------
{pullRequest["body"]}
--------------
# PATCH DETAILS:
--------------
{patchDetails}

"""
        with open(pullRequestPath, "a") as prFile:
            prFile.write(pullRequestContents)
            prFile.flush()


def saveCommits(repoSaveDirPath, commitsList = []):
    commitsPath = path.join(repoSaveDirPath, "commits")
    mkdir(commitsPath)

    for commit in commitsList:
        commitDetails = commit["commitDetails"]

        commitPath = path.join(commitsPath, f"{commit["author"]["login"]}_{commit["sha"]}")

        pullRequestContents = f"""# Commit {commit["sha"]}

-----------------
# URL: {commit["html_url"]}
-----------------
# EVIDENCE CHAIN:
{commit["evidenceChain"]}
-----------------
# COMMIT MESSAGE:
-----------------
{commit["commit"]["message"]}
-----------------
# COMMIT DETAILS:
-----------------
{"".join([f"{file["filename"]}\n{file["patch"]}\n\n" for file in commitDetails["files"]])}

"""
        with open(commitPath, "a") as prFile:
            prFile.write(pullRequestContents)
            prFile.flush()

def saveCommitComments(repoSaveDirPath, commitCommentsList = []):
    commitCommentsPath = path.join(repoSaveDirPath, "commit-comments")
    mkdir(commitCommentsPath)

    for commitComment in commitCommentsList:
        commitCommentPath = path.join(commitCommentsPath, f"{commitComment["user"]["login"]}_{commitComment["id"]}")

        commitCommentContents = f"""# Commit comment {commitComment["id"]}

-----------------
# URL: {commitComment["html_url"]}
-----------------
# EVIDENCE CHAIN:
{commitComment["evidenceChain"]}
-----------------
# COMMIT ID:
{commitComment["commit_id"]}
-----------------
# COMMIT COMMENT:
-----------------
@{commitComment["user"]["login"]} says on file {commitComment["path"]}, line {commitComment["line"]}, position {commitComment["position"]}:
{commitComment["body"]}

"""
        with open(commitCommentPath, "a") as commitCommentsFile:
            commitCommentsFile.write(commitCommentContents)
            commitCommentsFile.flush()

def saveIssues(repoSaveDirPath, issuesList = []):
    issuesPath = path.join(repoSaveDirPath, "issues")
    mkdir(issuesPath)

    for issue in issuesList:
        issuePath = path.join(issuesPath, f"{issue["user"]["login"]}_{issue["id"]}")

        issueContents = f"""# Issue {issue["id"]}

-----------------
# URL: {issue["html_url"]}
-----------------
# EVIDENCE CHAIN:
{issue["evidenceChain"]}
-----------------
# ISSUE:
Raised by @{issue["user"]["login"]}

# {issue["title"]}

{issue["body"]}

"""
        with open(issuePath, "a") as issueFile:
            issueFile.write(issueContents)
            issueFile.flush()

def saveIssueComments(repoSaveDirPath, issueCommentsList = []):
    issueComments = path.join(repoSaveDirPath, "issue-comments")
    mkdir(issueComments)

    for issueComment in issueCommentsList:
        issueCommentPath = path.join(issueComments, f"{issueComment["user"]["login"]}_{issueComment["id"]}")

        issueContents = f"""# Issue {issueComment["id"]}

-----------------
# ISSUE URL: {issueComment["issue_url"]}
# COMMENT URL: {issueComment["html_url"]}
-----------------
# EVIDENCE CHAIN:
{issueComment["evidenceChain"]}
-----------------
# ISSUE COMMENT:
@{issueComment["user"]["login"]} says:
{issueComment["body"]}

"""
        with open(issueCommentPath, "a") as issueFile:
            issueFile.write(issueContents)
            issueFile.flush()

def getPullRequests(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        if response.ok:
            responseJson = response.json()
            allItems.extend(responseJson)

        # Get the actual PR itself
        for i in range (0, len(allItems)):
            url = allItems[i]["patch_url"] if allItems[i]["patch_url"] != "" else allItems[i]["diff_url"]
            response = session.get(
                url=url
            )
            allItems[i]["patchDetails"] = response.text
    return allItems

def getIssues(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        if response.ok:
            responseJson = response.json()
            allItems.extend(responseJson)
    return allItems

def getIssueComments(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        if response.ok:
            responseJson = response.json()
            allItems.extend(responseJson)
    return allItems

def getCommitComments(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        if response.ok:
            responseJson = response.json()
            allItems.extend(responseJson)
    return allItems

def getForks(repoFullName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        if response.ok:
            responseJson = response.json()
            allItems.extend(responseJson)
    return allItems

def getGists(userOrOrgName = ""):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        if response.ok:
            responseJson = response.json()
            allItems.extend(responseJson)

        # Get the actual gist itself
        for i in range (0, len(allItems)):
            response = session.get(
                url=allItems[i]["url"]
            )
            responseJson = response.json()
            allItems[i]["gistDetails"] = responseJson
    return allItems

def getContributorsOfARepository(contributorsUrl):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        responseJson = response.json()
        allItems.extend(responseJson)
    return allItems

def getReposOwnedByUserOrOrg(userOrOrgName, isUser = True):
    isStartingFromPage2 = False
    nextUrl = ""
    allItems = []

    while True:
        # Make first request to get first batch of data and pagination information
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
        # Save next URL for next batch of processing
        try:
            nextUrl = response.links["next"]["url"]
        except KeyError:
            nextUrl = ""
            
        # Process current batch of data
        responseJson = response.json()
        if response.ok:
            items = responseJson["items"]
            allItems.extend(items)
        else:
            pass # TODO: responseJson.errors[0]
    return allItems

def searchForUser(name=""):
    response = session.get(
        url="https://api.github.com/search/users",
        params={
            "q": f"user:{name}"
        }
    )
    if response.ok:
        responseJson = response.json()
        result = responseJson["items"][0]
        return result
    else:
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
            # Save next URL for next batch of processing
            try:
                nextUrl = response.links["next"]["url"]
            except KeyError:
                nextUrl = ""

            # Process current batch of data
            responseJson = response.json()
            if response.ok:
                items = responseJson["items"]
                allItems.extend(items)
            else:
                pass # TODO: responseJson.errors[0]

        # Get the actual commit itself
        for i in range (0, len(allItems)):
            response = session.get(
                url=allItems[i]["url"]
            )
            responseJson = response.json()
            allItems[i]["commitDetails"] = responseJson

        return allItems
    
    # Get commits of a user/org
    else:
        allItems = []

        isStartingFromPage2 = False
        nextUrl = ""
        while True:
            # Make first request to get first batch of data and pagination information
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
            # Save next URL for next batch of processing
            try:
                nextUrl = response.links["next"]["url"]
            except KeyError:
                nextUrl = ""

            # Process current batch of data
            responseJson = response.json()
            if response.ok:
                items = responseJson["items"]
                allItems.extend(items)
            else:
                pass # TODO: responseJson.errors[0]

        isStartingFromPage2 = False
        nextUrl = ""
        while True:
            # Make first request to get first batch of data and pagination information
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
            # Save next URL for next batch of processing
            try:
                nextUrl = response.links["next"]["url"]
            except KeyError:
                nextUrl = ""

            # Process current batch of data
            responseJson = response.json()
            if response.ok:
                items = responseJson["items"]
                allItems.extend(items)
            else:
                pass # TODO: responseJson.errors[0]

        # Get the actual commit itself
        for i in range (0, len(allItems)):
            response = session.get(
                url=allItems[i]["url"]
            )
            responseJson = response.json()
            allItems[i]["commitDetails"] = responseJson

        return allItems


# Main function
def gather(outputDir, searchTerms=[], knownUsers=[], knownOrgs=[], maxSearchDepth=1):
    # TODO: https://github.com/trufflesecurity/trufflehog/releases

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
        print(f"[!] Failed to prepare output directory '{outputDir}'; error: {e}")
        return

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
                    if contributor["login"] not in list(map(lambda x: x["login"], linkedUsersOrOrgs)):
                        contributor["evidenceChain"] = [
                            f"Found contributor to repository '{repositoryToSearchIn["full_name"]}'"
                        ]
                        contributor["useForFurtherSearchDepth"] = searchDepth
                        linkedUsersOrOrgs.append(contributor)

                logText(f"[+] Search depth: {searchDepth}; found {len(contributors)} contributors to repository '{repositoryToSearchIn["full_name"]}'")

                # Find forks of existing repositories
                logText(f"[.] Search depth: {searchDepth}; finding forks of repository '{repositoryToSearchIn["full_name"]}'")
                forks = getForks(repoFullName=repositoryToSearchIn["full_name"])
                for fork in forks:
                    if fork["full_name"] not in list(map(lambda x: x["full_name"], repositoriesToSearchIn)):
                        fork["evidenceChain"] = [
                            f"Found fork '{fork["full_name"]}' of discovered repository '{repositoryToSearchIn["full_name"]}'"
                        ]
                        fork["useForFurtherSearchDepth"] = searchDepth + 1
                        repositoriesToSearchIn.append(fork)
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
                    if repository["name"] not in list(map(lambda x: x["name"], repositoriesToSearchIn)):
                        repository["evidenceChain"] = [
                            f"Found linked to {userOrOrg["type"].lower()} '{userOrOrg["login"]}', who is a contributor of repository '{repository["full_name"]}'"
                            ]
                        repository["useForFurtherSearchDepth"] = searchDepth + 1
                        repositoriesToSearchIn.append(repository)

                logText(f"[+] Search depth: {searchDepth}; found {len(repositories)} repositories owned by {userOrOrg["type"].lower()} '{userOrOrg["login"]}'")

        # Reduce search depth by 1 because all processing is done
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
        for i in range(0, len(commits)):
            commits[i]["evidenceChain"] = [
                f"Commit from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["allCommits"] = commits
        logText(f"\t[+] Found {len(commits)} commits in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All commit comments of the repository
        logText(f"\t[.] Finding all commit comments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        commitComments = getCommitComments(repoFullname=repositoriesToSearchIn[i]["full_name"])
        for i in range(0, len(commitComments)):
            commitComments[i]["evidenceChain"] = [
                f"Comment in commit {commitComments[i]["commit_id"]} in repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["commitComments"] = commitComments
        logText(f"\t[+] Found {len(commitComments)} commit comments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All issues of the repository
        logText(f"\t[.] Finding all issues in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        issues = getIssues(repoFullname=repositoriesToSearchIn[i]["full_name"])
        for i in range(0, len(issues)):
            issues[i]["evidenceChain"] = [
                f"Issue from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["issues"] = issues
        logText(f"\t[+] Found {len(issues)} issues in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All issue comments of the repository
        logText(f"\t[.] Finding all issue comments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        issueComments = getIssueComments(repoFullname=repositoriesToSearchIn[i]["full_name"])
        for i in range(0, len(issueComments)):
            issueComments[i]["evidenceChain"] = [
                f"Comment in issue '{issueComments[i]["html_url"]}' in repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
            ]
        repositoriesToSearchIn[i]["issueComments"] = issueComments
        logText(f"\t[+] Found {len(issueComments)} issueComments in repository '{repositoriesToSearchIn[i]["full_name"]}'...")

        # All PRs of the repository
        logText(f"\t[.] Finding all PRs in repository '{repositoriesToSearchIn[i]["full_name"]}'...")
        pullRequests = getPullRequests(repoFullname=repositoriesToSearchIn[i]["full_name"])
        for i in range(0, len(commits)):
            pullRequests[i]["evidenceChain"] = [
                f"PR {pullRequests[i]["number"]} from repository '{repositoriesToSearchIn[i]["full_name"]}'; repository's evidence chain: {repositoriesToSearchIn[i]["evidenceChain"]}"
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
    mkdir(allReposPath)
    for repositoryToSearchIn in repositoriesToSearchIn:
        repoPath = path.join(allReposPath, repositoryToSearchIn["full_name"].replace("/", "__"))
        mkdir(repoPath)

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

        cloneRepository(
            gitRepositoryCloneUrl=repositoryToSearchIn["clone_url"],
            gitRepositorySavePath=path.join(repoPath, repositoryToSearchIn["name"])
        )
        logText(f"\t [+] Cloned repo '{repositoryToSearchIn["full_name"]}'")

    # Run trufflehog
    runTrufflehog(
        logText=logText,
        outputDir=outputDir,
        repositoriesToSearchIn=repositoriesToSearchIn
    )

    # Close open files
    logOutputFile.close()
    resultsOutputFile.close() #TODO write results

