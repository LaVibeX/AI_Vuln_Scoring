# ai_scoring

## Getting started

To make it easy for you to get started with this project, here's a list of recommended next steps.

## Setup the Virtual Enviroment

- [ ] Create Virtual Enviroment
- [ ] Install Requirements
- [ ] Set Enviromental variables

```
python -m venv myvenv
source myvenv/bin/activate
pip install -r requirements.txt
touch .env
```
Add Tokens inside .env file:
- FREE_TOKEN #On-prem models
- GPT_TOKEN #Off-prem models
- GITHUB_TOKEN_LLM #Github API Token
- MODEL_URL1 #R&S Model URL
- OPENAI_API_KEY #In case you want to use your own OPEN_API key

## Download Information
In order to fetch the CVE Data from the different sources, you will need to .
- [ ] Open the jupyter notebook `notebook.ipynb`
- [ ] Click on `Run all`

## Visualize the information

- [ ] Open streamlit
```
streamlit run ./scripts/frontend.py
```

## License
This project is licensed under the GPL-v3 License.


