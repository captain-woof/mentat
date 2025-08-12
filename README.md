# mentat
OSINT automation for pentests and red team engagements.

## Installation

### Set up
```
sudo apt install libcurl4-openssl-dev libssl-dev python3-dev

python3 -m virtualenv venv
source ./venv/bin/activate

pip3 install -r requirements.txt
```

### Environment variables

Use the provided `.env.example` as a template for the `.env` file.

```
cp ./.env.example ./.env
# now edit the .env
```