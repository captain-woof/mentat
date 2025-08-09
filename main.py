from argparse import ArgumentParser
from os import path
import dotenv
import dehashed
import linkedin
import sensitive

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
    parserLinkedin.add_argument("--wait-before-pagination-min", action="store", type=float, help="Minimum number of seconds to wait before going to next page; default: 3.0", default=3.0)
    parserLinkedin.add_argument("--wait-before-pagination-max", action="store", type=float, help="Maximum number of seconds to wait before going to next page; default: 5.0", default=5.0)

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
    parserSensitive.add_argument("--wait-before-pagination-min", action="store", type=float, help="Minimum number of seconds to wait before going to next page; default: 3.0", default=3.0)
    parserSensitive.add_argument("--wait-before-pagination-max", action="store", type=float, help="Maximum number of seconds to wait before going to next page; default: 5.0", default=5.0)

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
        linkedin.gather(companyNames=companyNames, companyDomains=companyDomains, outputPath=outputPath)

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
            waitBeforePaginationMax=waitBeforePaginationMax
            )