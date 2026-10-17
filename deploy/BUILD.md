# Reproduzir a distribuição

As releases já incluem os três agentes genéricos. Eles não contêm credenciais de clientes: a central adiciona o cadastro ao gerar o instalador ou comando.

1. Windows: Python 3.12, dependências de `requirements-python.txt`, PyInstaller e pywin32; execute `python scripts/build-python-windows.py --python CAMINHO_DO_PYTHON`. O build não instala o agente no computador.
2. Linux: execute `python scripts/build-python-linux.py`. O script baixa runtime e wheels públicos, confere os hashes e gera `dist/O3CloudCentral-linux-amd64.tar.gz`.
3. pfSense: com Python 3.14+ (ou suporte zstandard), execute `python scripts/package-python-pfsense.py`. Ele gera o stage com runtime FreeBSD e manifesto. Em FreeBSD 14 amd64, extraia o stage em diretório temporário e use `pkg create -M stage/manifest.json -r stage -o output`. Não é necessário instalar o pacote na máquina de build. Copie o .pkg resultante para `dist`.
4. Execute `python scripts/release.py`. Ele inclui somente código e os artefatos genéricos esperados, gera `dist/RELEASE.json`, o bundle e `dist/SHA256SUMS`.

Os manifestos de dependências em `scripts` registram as origens e SHA-256 usados nos agentes. O instalador da central usa `requirements-central.lock` com versões e hashes dos wheels.

Para os testes Python, configure `PYTHONPATH=python` e execute `python -m pytest python/tests`. Os testes SQL exigem um MariaDB de teste separado; jamais aponte a variável de testes para o banco da aplicação. Os testes que exigem outro sistema operacional são ignorados quando esse sistema não está disponível.

Os testes da interface usam Playwright: `node scripts/ui-smoke.cjs` e `node scripts/ui-auth-smoke.cjs`. Ajuste `NODE_PATH` ou instale o Playwright no ambiente de desenvolvimento; o navegador padrão desses scripts é Edge, selecionável por `BROWSER_CHANNEL`.
