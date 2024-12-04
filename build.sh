#!/usr/bin/env bash
py3=python3.12
cwd=$(dirname "${0}")

${py3} -m pip install --upgrade -r "${cwd}/requirements.txt"

${py3} -m PyInstaller --onefile --clean --log-level INFO \
  --name tls-simple "${cwd}/src/__main__.py" \
&& [[ -d "${cwd}/build" ]] && rm -rf "${cwd}/build" 