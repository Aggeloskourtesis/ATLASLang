# ATLASLang
Domain Specific Language (DSL) using the Meta-Attack Language for MITRE ATLAS (still under construction)

Additional MAL and Python files may be included for individual attack scenarios and experiments.

## Requirements

The project requires:

- Python 3
- Python `venv`
- `pip`

All required Python packages and their versions are included in:

```text
requirements.txt
```

A dedicated Python virtual environment is recommended.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Aggeloskourtesis/ATLASLang.git
cd ATLASLang
```

### 2. Create a virtual environment

Create a new Python virtual environment:

```bash
python3 -m venv .venv-atlas
```

Activate it:

```bash
source .venv-atlas/bin/activate
```

After activation, the terminal should display the virtual environment name, for example:

```text
(.venv-atlas) user@machine:~/ATLASLang$
```

### 3. Upgrade pip

```bash
python -m pip install --upgrade pip
```

### 4. Install the dependencies

Install all required packages from `requirements.txt`:

```bash
python -m pip install -r requirements.txt
```

This installs the Python dependencies required by the project, including the MAL-related packages used to create and simulate the models.

You can verify the installed packages with:

```bash
python -m pip list
```

## Running the Simulation

Make sure the virtual environment is active:

```bash
source .venv-atlas/bin/activate
```

Then run the simulation:

```bash
python atlas_simulation.py
```

The simulation script loads the MAL language definitions, creates the corresponding MAL model and attack graph, and executes the configured attack scenario.

## Acknowledgements

ATLASLang is developed using the Meta Attack Language (MAL) framework.

Parts of the cybersecurity modeling functionality of ATLASLang are based on and/or adapted from
[enterpriseLang](https://github.com/mal-lang/enterpriseLang), a MAL-based domain-specific language
for modeling enterprise cybersecurity using the MITRE ATT&CK framework.

We gratefully acknowledge the enterpriseLang authors and contributors for their work.

If you use ATLASLang, please also consider citing the original enterpriseLang publication:

W. Xiong, E. Legrand, O. Åberg, and R. Lagerström,
"Cyber security threat modeling based on the MITRE Enterprise ATT&CK Matrix,"
Software and Systems Modeling, 2021.
https://doi.org/10.1007/s10270-021-00898-7
