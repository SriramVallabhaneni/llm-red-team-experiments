# LLM Red Team Experiment

An automated framework for testing large language model deployments against known attack vectors, logging results, and generating structured security reports.

Built as a security research tool to evaluate how well LLM-powered applications resist prompt injection, jailbreaking, and indirect injection attacks.

## Features

- **3 attack modules** — prompt injection, jailbreak, and indirect injection
- **Automated scoring** — keyword-based evaluator classifies findings as critical, high, medium, or low
- **Detection tracking** — distinguishes between attacks that were explicitly flagged vs silently ignored
- **SQLite logging** — every prompt, response, and score is persisted across runs for comparison
- **HTML report generation** — professional report with executive summary, findings by attack type, and detailed results

## Project Structure
```
llm-experiments/
├── attacks/
│   ├── prompt_injection.py   # System prompt extraction attempts
│   ├── jailbreak.py          # Behavioral constraint bypass attempts  
│   └── indirect_injection.py # Injections embedded in documents/data
├── core/
│   ├── config.py             # Model, database, and attack settings
│   ├── logger.py             # SQLite database layer
│   └── reporter.py           # HTML report generation
├── data/                     # SQLite database (gitignored)
├── reports/                  # Generated HTML reports (gitignored)
├── main.py                   # Entry point
└── requirements.txt
```

## Setup
```bash
git clone https://github.com/SriramVallabhaneni/llm-red-team-experiments.git
cd llm-experiments
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Create a `.env` file in the project root:
```
ANTHROPIC_API_KEY=your-key-here
```

## Usage
```bash
python3 main.py
```

The framework will run all enabled attack modules against the configured model and generate an HTML report in the `reports/` directory.

To toggle attack modules or change the target model, edit `core/config.py`:
```python
MODEL = "claude-haiku-4-5-20251001"

ATTACKS = {
    "prompt_injection": True,
    "jailbreak": True,
    "indirect_injection": True
}
```

## Attack Modules

**Prompt Injection** — attempts to extract system prompt contents or override model instructions through direct user input. Tests 8 vectors including instruction overrides, fake system prompts, translation exfiltration, and completion attacks.

**Jailbreak** — attempts to bypass behavioral constraints through roleplay, fictional framing, academic framing, false authority claims, and encoding obfuscation. Tests 10 vectors across 6 categories.

**Indirect Injection** — embeds malicious instructions inside documents, emails, feedback forms, and transaction logs that the model is asked to process. Tests 8 vectors and tracks whether each attack was explicitly detected or silently ignored by the model.

## Key Finding

During indirect injection testing, attacks that embedded instructions inside structured data (transaction logs, research abstracts, feedback forms) consistently failed silently — the model processed the legitimate content without flagging the injected instructions. Attacks using more explicit or conversational injection language were more likely to be detected and refused. This suggests structured data injection represents a higher residual risk than explicit instruction injection against well-aligned models.

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications)
- [MITRE ATLAS](https://atlas.mitre.org)
- [Greshake et al. — Indirect Prompt Injection (2023)](https://arxiv.org/abs/2302.12173)
- [Carlini et al. — Extracting Training Data from LLMs (2021)](https://arxiv.org/abs/2012.07805)
