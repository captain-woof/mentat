# mentat
OSINT automation for pentests and red team engagements.

## Installation

### Set up

#### Python3

You need Python3.14+ to run this.

#### Required libraries
```bash
sudo apt update -y
sudo apt install libcurl4-openssl-dev libssl-dev python3 python3-dev libxml2-dev libxslt1-dev zlib1g-dev build-essential libyaml-dev

python3 -m virtualenv venv
source ./venv/bin/activate

pip3 --no-cache-dir install --verbose  --force-reinstall -r requirements.txt # if you get `lxml` errors here, remove the `lxml` package's version number in the `requirements.txt` file and try again.
```

#### Trufflehog

Also download Trufflehog v3 from [https://github.com/trufflesecurity/trufflehog/releases/latest](https://github.com/trufflesecurity/trufflehog/releases/latest), and put the `trufflehog` binary somewhere on your `PATH`. Tested with [v3.99.8](https://github.com/trufflesecurity/trufflehog/releases/tag/v3.99.8).

### Environment variables

Use the provided `.env.example` as a template for the `.env` file.

```
cp ./.env.example ./.env
# now edit the .env
```

#### GitHub

For GitHub PAT token in environment variable `GITHUB_PAT_TOKEN`, obtain yours at [github.com/settings/tokens](https://github.com/settings/tokens).

## Running

```bash
python3 main.py --help
python3 main.py [module-name] --help
```