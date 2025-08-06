from argparse import ArgumentParser
from os import path
import dotenv
import dehashed
import linkedin

# Load env vars
dotenv.load_dotenv()

# MAIN
if __name__ == "__main__":
    # Parse arguments
    parser = ArgumentParser(description="Mentat helps automating OSINT searches and processing data")
    subparsers = parser.add_subparsers(dest="mode", description="Module to run. Each module has its own usage and instructions", required=True)

    ## Linkedin
    parserLinkedin = subparsers.add_parser('linkedin', help='Enumerate employees on Linkedin with Google search')
    parserLinkedin.add_argument("--company-domains", action="append", help="Domain of the company; can use multiple", default=[])
    parserLinkedin.add_argument("--company-names", action="append", help="Name of the company; can use multiple", default=[])
    parserLinkedin.add_argument("--output-path", action="store", help="Directory to store all output and downloaded files in; default: ./output", default=path.join(path.curdir, "output"))

    ## DeHased
    parserDehashed = subparsers.add_parser('dehashed', help='Search on DeHashed for breached data (requires account)')
    parserDehashed.add_argument("--company-names", action="append", help="Name of the company; can use multiple", default=[])
    parserDehashed.add_argument("--company-domains", action="append", help="Domain of the company; can use multiple", default=[])
    parserDehashed.add_argument("--output-path", action="store", help="Directory to store all output and downloaded files in; default: ./output", default=path.join(path.curdir, "output"))

    args = parser.parse_args()
    companyNames = args.company_names
    companyDomains = args.company_domains
    outputPath = args.output_path

    # Dehashed
    if args.mode == "dehashed":
        dehashed.gather(companyNames=companyNames, companyDomain=companyDomains, outputPath=outputPath)

    # LinkedIn
    elif args.mode == "linkedin":
        linkedin.gather(companyNames=companyNames, companyDomains=companyDomains, outputPath=outputPath)

    # TODO: add more