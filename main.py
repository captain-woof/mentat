from argparse import ArgumentParser
from os import path
import dotenv
import dehashed

# Load env vars
dotenv.load_dotenv()

# MAIN
if __name__ == "__main__":
    # Parse arguments
    parser = ArgumentParser()

    parser.add_argument("--company-name", action="append", help="Name of the company; can use multiple", default=[])
    parser.add_argument("--company-domain", action="append", help="Domain of the company; can use multiple", default=[])
    parser.add_argument("--output-path", action="store", help="Directory to store all output and downloaded files in; default: ./output", default=path.join(path.curdir, "output"))

    args = parser.parse_args()
    companyName = args.company_name
    companyDomain = args.company_domain
    outputPath = args.output_path

    # Dehashed
    dehashed.gather(companyName=companyName, companyDomain=companyDomain, outputPath=outputPath)