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
    parser = ArgumentParser()

    parser.add_argument("--company-name", action="append", help="Name of the company; can use multiple", default=[])
    parser.add_argument("--company-domain", action="append", help="Domain of the company; can use multiple", default=[])
    parser.add_argument("--output-path", action="store", help="Directory to store all output and downloaded files in; default: ./output", default=path.join(path.curdir, "output"))
    parser.add_argument("--dehashed", action="store_true", help="Acquire data from DeHashed")
    parser.add_argument("--linkedin", action="store_true", help="Acquire data from LinkedIn")

    args = parser.parse_args()
    companyName = args.company_name
    companyDomain = args.company_domain
    outputPath = args.output_path

    # Dehashed
    if args.dehashed:
        dehashed.gather(companyNames=companyName, companyDomain=companyDomain, outputPath=outputPath)

    # LinkedIn
    if args.linkedin:
        linkedin.gather(companyNames=companyName, companyDomains=companyDomain, outputPath=outputPath)

    # Google

    # Yandex

    # Baidu