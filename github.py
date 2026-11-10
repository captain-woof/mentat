from requests import Session
from requests_ratelimiter import LimiterAdapter
from os import environ, mkdir, path

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
        return allItems


# Main function
def gather(outputDir, searchTerms=[], knownUsers=[], knownOrgs=[], maxSearchDepth=1):
    # TODO: https://github.com/trufflesecurity/trufflehog/releases

    # Persistent data
    repositoriesToSearchIn = [] # [{  }]
    linkedUsersOrOrgs = []
    gistsToSearchIn = []
    commitsToSearchIn = []

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

    # Follow search depth, and gather more target repositories
    newRepositoriesFound = []
    searchDepth = 1

    if maxSearchDepth != 1:
        logText("[.] Finding contributors to above found repositories, then other repositories owned by them...")
    while searchDepth != maxSearchDepth:
        # Make set of contributors
        newContributorUserOrOrgsFound = []
        for repositoryToSearchIn in repositoriesToSearchIn if len(newRepositoriesFound) == 0 else newRepositoriesFound:
            logText(f"[.] Search depth: {searchDepth}; finding contributors to repository '{repositoryToSearchIn["full_name"]}'")

            contributors = getContributorsOfARepository(
                contributorsUrl=repositoryToSearchIn["contributors_url"]
            )
            for contributor in contributors:
                if contributor["login"] not in list(map(lambda x: x["login"], newContributorUserOrOrgsFound)):
                    newContributorUserOrOrgsFound.append(contributor)
                if contributor["login"] not in list(map(lambda x: x["login"], linkedUsersOrOrgs)):
                    contributor["evidenceChain"] = [
                        f"Found contributor to repository '{repositoryToSearchIn["full_name"]}'"
                    ]
                    linkedUsersOrOrgs.append(contributor)

            logText(f"[+] Search depth: {searchDepth}; found {len(contributors)} contributors to repository '{repositoryToSearchIn["full_name"]}'")
        newRepositoriesFound.clear()

        # Make set of repositories to process
        for userOrOrg in newContributorUserOrOrgsFound:
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

                    repositoriesToSearchIn.append(repository)
                    newRepositoriesFound.append(repository)

            logText(f"[+] Search depth: {searchDepth}; found {len(repositories)} repositories owned by {userOrOrg["type"].lower()} '{userOrOrg["login"]}'")

        # Reduce search depth by 1 because all processing is done
        searchDepth += 1

    # Gist of users: knownUsers + knownOrgs + linkedUsersOrOrgs
    logText("[.] Finding gists...")

    for userOrOrg in knownUsers + knownOrgs:
        response = getGists(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was provided by user"
            ]
        gistsToSearchIn.extend(response)

        logText(f"[+] found {len(response)} gists by provided user/organisation '{userOrOrg["login"]}'")
    for userOrOrg in linkedUsersOrOrgs:
        response = getGists(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was found linked to a discovered repository. User/org's evidence chain: {userOrOrg["evidenceChain"]}"
            ]
        gistsToSearchIn.extend(response)
        
        logText(f"[+] found {len(response)} gists by discovered user/organisation '{userOrOrg["login"]}'")


    # Commits by users: knownUsers + knownOrgs + linkedUsersOrOrgs
    logText("[.] Finding commits by users and organsations...")

    for userOrOrg in knownUsers + knownOrgs:
        response = getCommits(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was provided by user"
            ]
        commitsToSearchIn.extend(response)

        logText(f"[+] found {len(response)} commits by given user/organisation '{userOrOrg["login"]}'")

    for userOrOrg in linkedUsersOrOrgs:
        response = getCommits(userOrOrgName=userOrOrg["login"])
        for i in range(0, len(response)):
            response[i]["evidenceChain"] = [
                f"From user/organisation '{userOrOrg["login"]}' which was found linked to a discovered repository. User/org's evidence chain: {userOrOrg["evidenceChain"]}"
            ]
        commitsToSearchIn.extend(response)

        logText(f"[+] found {len(response)} gists by discovered user/organisation '{userOrOrg["login"]}'")

    # Process repos: forks, commits, comments. issues, issue comments, contents


    # Close open files
    logOutputFile.close()
    resultsOutputFile.close()

    # 

    """
        inside items:
        {
            "id": 844388579,
            "node_id": "R_kgDOMlRY4w",
            "name": "malware-study",
            "full_name": "captain-woof/malware-study",
            "private": false,
            "owner": {
                "login": "captain-woof",
                "id": 72122026,
                "node_id": "MDQ6VXNlcjcyMTIyMDI2",
                "avatar_url": "https://avatars.githubusercontent.com/u/72122026?v=4",
                "gravatar_id": "",
                "url": "https://api.github.com/users/captain-woof",
                "html_url": "https://github.com/captain-woof",
                "followers_url": "https://api.github.com/users/captain-woof/followers",
                "following_url": "https://api.github.com/users/captain-woof/following{/other_user}",
                "gists_url": "https://api.github.com/users/captain-woof/gists{/gist_id}",
                "starred_url": "https://api.github.com/users/captain-woof/starred{/owner}{/repo}",
                "subscriptions_url": "https://api.github.com/users/captain-woof/subscriptions",
                "organizations_url": "https://api.github.com/users/captain-woof/orgs",
                "repos_url": "https://api.github.com/users/captain-woof/repos",
                "events_url": "https://api.github.com/users/captain-woof/events{/privacy}",
                "received_events_url": "https://api.github.com/users/captain-woof/received_events",
                "type": "User",
                "user_view_type": "public",
                "site_admin": false
            },
            "html_url": "https://github.com/captain-woof/malware-study",
            "description":"My projects to understand malware development and detection. Use responsibly. I\'m not responsible if you cause unauthorised damage to anyone\'s system.",
            "fork": false,
            "url": "https://api.github.com/repos/captain-woof/malware-study",
            "forks_url": "https://api.github.com/repos/captain-woof/malware-study/forks",
            "keys_url": "https://api.github.com/repos/captain-woof/malware-study/keys{/key_id}",
            "collaborators_url": "https://api.github.com/repos/captain-woof/malware-study/collaborators{/collaborator}",
            "teams_url": "https://api.github.com/repos/captain-woof/malware-study/teams",
            "hooks_url": "https://api.github.com/repos/captain-woof/malware-study/hooks",
            "issue_events_url": "https://api.github.com/repos/captain-woof/malware-study/issues/events{/number}",
            "events_url": "https://api.github.com/repos/captain-woof/malware-study/events",
            "assignees_url": "https://api.github.com/repos/captain-woof/malware-study/assignees{/user}",
            "branches_url": "https://api.github.com/repos/captain-woof/malware-study/branches{/branch}",
            "tags_url": "https://api.github.com/repos/captain-woof/malware-study/tags",
            "blobs_url": "https://api.github.com/repos/captain-woof/malware-study/git/blobs{/sha}",
            "git_tags_url": "https://api.github.com/repos/captain-woof/malware-study/git/tags{/sha}",
            "git_refs_url": "https://api.github.com/repos/captain-woof/malware-study/git/refs{/sha}",
            "trees_url": "https://api.github.com/repos/captain-woof/malware-study/git/trees{/sha}",
            "statuses_url": "https://api.github.com/repos/captain-woof/malware-study/statuses/{sha}",
            "languages_url": "https://api.github.com/repos/captain-woof/malware-study/languages",
            "stargazers_url": "https://api.github.com/repos/captain-woof/malware-study/stargazers",
            "contributors_url": "https://api.github.com/repos/captain-woof/malware-study/contributors",
            "subscribers_url": "https://api.github.com/repos/captain-woof/malware-study/subscribers",
            "subscription_url": "https://api.github.com/repos/captain-woof/malware-study/subscription",
            "commits_url": "https://api.github.com/repos/captain-woof/malware-study/commits{/sha}",
            "git_commits_url": "https://api.github.com/repos/captain-woof/malware-study/git/commits{/sha}",
            "comments_url": "https://api.github.com/repos/captain-woof/malware-study/comments{/number}",
            "issue_comment_url": "https://api.github.com/repos/captain-woof/malware-study/issues/comments{/number}",
            "contents_url": "https://api.github.com/repos/captain-woof/malware-study/contents/{+path}",
            "compare_url": "https://api.github.com/repos/captain-woof/malware-study/compare/{base}...{head}",
            "merges_url": "https://api.github.com/repos/captain-woof/malware-study/merges",
            "archive_url": "https://api.github.com/repos/captain-woof/malware-study/{archive_format}{/ref}",
            "downloads_url": "https://api.github.com/repos/captain-woof/malware-study/downloads",
            "issues_url": "https://api.github.com/repos/captain-woof/malware-study/issues{/number}",
            "pulls_url": "https://api.github.com/repos/captain-woof/malware-study/pulls{/number}",
            "milestones_url": "https://api.github.com/repos/captain-woof/malware-study/milestones{/number}",
            "notifications_url": "https://api.github.com/repos/captain-woof/malware-study/notifications{?since,all,participating}",
            "labels_url": "https://api.github.com/repos/captain-woof/malware-study/labels{/name}",
            "releases_url": "https://api.github.com/repos/captain-woof/malware-study/releases{/id}",
            "deployments_url": "https://api.github.com/repos/captain-woof/malware-study/deployments",
            "created_at": "2024-08-19T06:47:08Z",
            "updated_at": "2026-11-08T09:21:34Z",
            "pushed_at": "2026-05-04T14:33:03Z",
            "git_url": "git://github.com/captain-woof/malware-study.git",
            "ssh_url": "git@github.com:captain-woof/malware-study.git",
            "clone_url": "https://github.com/captain-woof/malware-study.git",
            "svn_url": "https://github.com/captain-woof/malware-study",
            "homepage": "",
            "size": 422156,
            "stargazers_count": 113,
            "watchers_count": 113,
            "language": "C",
            "has_issues": true,
            "has_projects": true,
            "has_wiki": true,
            "has_pages": false,
            "has_discussions": false,
            "forks_count": 18,
            "mirror_url": null,
            "archived": false,
            "disabled": false,
            "open_issues_count": 0,
            "license": null,
            "allow_forking": true,
            "is_template": false,
            "web_commit_signoff_required": false,
            "has_pull_requests": true,
            "pull_request_creation_policy": "all",
            "topics": [
                "malware-analysis",
                "malware-development",
                "malware-protection",
                "malware-research"
            ],
            "visibility": "public",
            "forks": 18,
            "open_issues": 0,
            "watchers": 113,
            "default_branch": "main",
            "permissions": {
                "admin": true,
                "maintain": true,
                "push": true,
                "triage": true,
                "pull": true
            },
            "score": 1.0,
            "text_matches": []
        },
        """
    