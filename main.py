from argparse import ArgumentParser
from os import environ, path
import sys
import dotenv
import dehashed
import linkedin
import sensitive
import hostname_fuzzer
import github

# Load env vars
dotenv.load_dotenv()

# MAIN
if __name__ == "__main__":
    # Parse arguments
    parser = ArgumentParser(description="Mentat helps automating OSINT searches and processing data")
    subparsers = parser.add_subparsers(dest="mode", description="Module to run. Each module has its own usage and instructions.", required=True)

    ## Linkedin
    parserLinkedin = subparsers.add_parser('linkedin', description='Enumerate employees on Linkedin with Google search')
    parserLinkedin.add_argument("--company-domains", action="append", help="Domain of the company; can use multiple", default=[])
    parserLinkedin.add_argument("--company-names", action="append", help="Name of the company; can use multiple", default=[])
    parserLinkedin.add_argument("--output-path", action="store", help="Directory to store all output and downloaded files in; default: ./output", default=path.join(path.curdir, "output"))
    parserLinkedin.add_argument("--ssh", nargs="*", help="SOCKS5 proxies with SSH login; only one will be randomly chosen; format: USER1@HOST1 USER2@HOST2...", default=[])
    parserLinkedin.add_argument("--sshKey", action="store", help="Private key filepath for SSH login", default="")
    parserLinkedin.add_argument("--wait-before-pagination-min", action="store", type=float, help="Minimum number of seconds to wait before going to next page; default: 10.0", default=10.0)
    parserLinkedin.add_argument("--wait-before-pagination-max", action="store", type=float, help="Maximum number of seconds to wait before going to next page; default: 20.0", default=20.0)

    ## DeHashed
    parserDehashed = subparsers.add_parser('dehashed', description='Search on DeHashed for breached data (requires account)')
    parserDehashed.add_argument("--company-names", action="append", help="Name of the company; can use multiple", default=[])
    parserDehashed.add_argument("--company-domains", action="append", help="Domain of the company; can use multiple", default=[])
    parserDehashed.add_argument("--output-path", action="store", help="Directory to store all output and downloaded files in; default: ./output", default=path.join(path.curdir, "output"))

    ## Sensitive data
    parserSensitive = subparsers.add_parser('sensitive', description='Search for exposed sensitive information on multiple sites and take screenshots for quick triage')
    parserSensitive.add_argument("--company-names", action="append", help="Name of the company; can use multiple", default=[])
    parserSensitive.add_argument("--company-domains", action="append", help="Domain of the company; can use multiple", default=[])
    parserSensitive.add_argument("--output-path", action="store", help="Directory to store all output and downloaded files in; default: ./output", default=path.join(path.curdir, "output"))
    parserSensitive.add_argument("--ssh", nargs="*", help="Use SOCKS5 proxies with SSH login; each proxy spawns an independent browser; format: USER1@HOST1 USER2@HOST2...", default=[])
    parserSensitive.add_argument("--sshKey", action="store", help="Private key filepath for SSH login", default="")
    parserSensitive.add_argument("--wait-before-pagination-min", action="store", type=float, help="Minimum number of seconds to wait before going to next page; default: 45.0", default=45.0)
    parserSensitive.add_argument("--wait-before-pagination-max", action="store", type=float, help="Maximum number of seconds to wait before going to next page; default: 75.0", default=75.0)
    parserSensitive.add_argument("--skip-company-domains", action="store_true", help="Skips Google dorks for searching in company (sub)domains; only third-party sites are searched", default=False)
    parserSensitive.add_argument("--skip-third-party", action="store_true", help="Skips Google dorks for searching in third-party sites; only company (sub)domains are searched", default=False)

    ## Hostname fuzzer
    parserHostnameFuzzer = subparsers.add_parser('hostname-fuzzer', description='Fuzzes for valid hostnames for HTTP(s) servers, by using input lists of domains and IP:PORTs to try.')
    parserHostnameFuzzer.add_argument("-d", "--domains", action="store", help="List of domains to try", required=True)
    parserHostnameFuzzer.add_argument("-i", "--ip-ports", action="store", help="List of IP:PORTs to try (newline separated)", required=True)
    parserHostnameFuzzer.add_argument("--output-csv", action="store", help="CSV output path; default: ./results.csv", default=path.join(path.curdir, "results.csv"))
    parserHostnameFuzzer.add_argument("-t", "--timeout", action="store", type=int, help="Request timeout in seconds; default: 10", default=10)
    parserHostnameFuzzer.add_argument("-r", "--retries", action="store", type=int, help="Maximum retries; default: 2", default=2)
    parserHostnameFuzzer.add_argument("-m", "--max-requests", action="store", type=int, help="Maximum requests per second; default: 100", default=100)

    ## GitHub
    parserGithub = subparsers.add_parser('github', description='Search for secrets in GitHub repositories')
    parserGithub.add_argument("-s", "--search-terms", action="append", help="Search term to search for in all repositories; can use multiple; example: 'SSH_KEY'", default=[])
    parserGithub.add_argument("-u", "--known-users", action="append", help="Known usernames to search for connected repositories; can use multiple; example: 'captain-woof'", default=[])
    parserGithub.add_argument("-o", "--known-orgs", action="append", help="Known organization names to search for connected repositories; can use multiple; example: 'r-spacex'", default=[])
    parserGithub.add_argument("-d", "--search-depth", action="store", type=int, help="Recursive search depth; if 1, it only searches for target users/orgs and their owned repositories. If 2, it does the same + looks up the contributors to the found repositories and searches in their owned repositories. And so on...; default: 1", default=1)
    parserGithub.add_argument("-od", "--output-dir", action="store", help="Output directory for everything; it is advised to make a fresh directory for this.")
    parserGithub.add_argument("--no-color", action="store_true", help="Disable coloured STDOUT output; the log file is always plain; colour is also auto-disabled when STDOUT is not a terminal", default=False)
    

    args = parser.parse_args()

    # Dehashed
    if args.mode == "dehashed":
        companyNames = args.company_names
        companyDomains = args.company_domains
        outputPath = args.output_path
        dehashed.gather(companyNames=companyNames, companyDomain=companyDomains, outputPath=outputPath)

    # LinkedIn
    elif args.mode == "linkedin":
        companyNames = args.company_names
        companyDomains = args.company_domains
        outputPath = args.output_path
        waitBeforePaginationMin = args.wait_before_pagination_min
        waitBeforePaginationMax = args.wait_before_pagination_max
        linkedin.gather(
            companyNames=companyNames,
            companyDomains=companyDomains,
            outputPath=outputPath,
            waitBeforePaginationMin=waitBeforePaginationMin,
            waitBeforePaginationMax=waitBeforePaginationMax,
            sshLogins=args.ssh,
            sshLoginsKey=args.sshKey
            )

    # Sensitive data
    elif args.mode == "sensitive":
        companyNames = args.company_names
        companyDomains = args.company_domains
        outputPath = args.output_path
        waitBeforePaginationMin = args.wait_before_pagination_min
        waitBeforePaginationMax = args.wait_before_pagination_max
        sensitive.gather(
            companyNames=companyNames,
            companyDomains=companyDomains,
            outputPath=outputPath,
            waitBeforePaginationMin=waitBeforePaginationMin,
            waitBeforePaginationMax=waitBeforePaginationMax,
            sshLogins=args.ssh,
            sshLoginsKey=args.sshKey,
            skipCompanyDomains=args.skip_company_domains,
            skipThirdParty=args.skip_third_party
            )
        
    # Hostname fuzzer
    elif args.mode == "hostname-fuzzer":
        domainsFile = args.domains
        ipPortsFile = args.ip_ports
        outputCsvFilePath = args.output_csv
        timeout = args.timeout
        retries = args.retries
        maxRequests = args.max_requests
        hostname_fuzzer.start(
            domainsFile=domainsFile,
            ipPortsFile=ipPortsFile,
            maxRequests=maxRequests,
            outputCsvFilePath=outputCsvFilePath,
            retries=retries,
            timeout=timeout
            )

    elif args.mode == "github":
        searchTerms = args.search_terms
        knownUsers = args.known_users
        knownOrgs = args.known_orgs
        searchDepth = args.search_depth
        outputDir = args.output_dir

        # Load all env vars for this module here
        githubPatToken = environ.get("GITHUB_PAT_TOKEN")
        if githubPatToken in [None, ""]:
            print("[!] GitHub PAT Token not found. Check your .env.")
            sys.exit(1)

        github.gather(
            searchTerms=searchTerms,
            knownUsers=knownUsers,
            knownOrgs=knownOrgs,
            maxSearchDepth=searchDepth,
            outputDir=outputDir,
            githubPatToken=githubPatToken,
            noColor=args.no_color
        )
