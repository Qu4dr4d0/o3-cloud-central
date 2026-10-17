# Instalação e recuperação da central

O caminho recomendado está no [README](../README.md). Use uma VM Ubuntu dedicada; não execute o instalador da central dentro de um pfSense ou em um terminal de usuário.

## O que é instalado

| Caminho | Conteúdo |
|---|---|
| /opt/o3cloudcentral/releases | Código das versões instaladas |
| /opt/o3cloudcentral/venvs | Ambientes Python separados por instalação |
| /opt/o3cloudcentral/current e /opt/o3cloudcentral/venv | Links para a versão ativa |
| /var/lib/edgehub | CA, identidade TLS e artefatos dos agentes; acesso restrito |
| /etc/o3cloudcentral.env | Configuração do serviço |
| /etc/o3cloudcentral-install.json | Identificação da instalação, URL e etapas concluídas |
| /etc/o3cloudcentral/ca.crt | Cópia pública da CA para confiar no navegador |
| /etc/systemd/system/o3cloudcentral.service | Serviço da central |

Os nomes internos `edgehub` são mantidos por compatibilidade. O serviço executa com usuário dedicado sem login; conecta ao MariaDB via socket Unix e autenticação do usuário local. Somente esse banco recebe permissões. Os arquivos de código pertencem ao root.

## Distribuição local

Se a VM não puder baixar a release diretamente, transfira o arquivo da release e o SHA256SUMS por um canal confiável, confira o SHA-256 e extraia. A instalação ainda precisa dos repositórios Ubuntu e do PyPI.

```bash
sha256sum --check SHA256SUMS --ignore-missing
tar -xzf o3-cloud-central-0.6.6.tar.gz
cd o3-cloud-central-0.6.6
sudo python3 deploy/install-central.py --url https://10.20.0.10:8443
```

## Instalação interrompida

O instalador preserva os dados quando falha. Corrija acesso à Internet, espaço ou dependências e execute novamente com a mesma URL. Não apague o banco nem os arquivos da CA para contornar uma mensagem.

Se uma inicialização foi interrompida durante a criação da identidade e ainda não concluiu o banco, ele pode recusar prosseguir ao encontrar uma PKI parcial. Preserve o diretório e consulte o erro nos registros para fazer uma recuperação assistida. Essa recusa evita sobrescrever uma identidade que já possa estar em uso.

Se a atualização de uma central existente falhar no teste HTTPS, o instalador tenta reativar o código e o ambiente Python anteriores. Não faz rollback destrutivo do banco. Verifique `systemctl status o3cloudcentral` e `journalctl -u o3cloudcentral`.

## Testes de imagem

`--prepare-only` prepara os arquivos, o MariaDB e a unidade, sem iniciar a central. Esse modo existe para testes de imagem/container; a instalação normal exige systemd em execução. Em uma VM preparada, finalize iniciando `sudo systemctl enable --now o3cloudcentral` e confira o acesso HTTPS antes de utilizá-la.

## URL e acesso

Mantenha o DNS/IP da URL estável e alcançável pelos pfSenses. Alterar a URL ou migrar a central para uma instalação prévia de laboratório exige um procedimento específico; o instalador não adota bancos desconhecidos nem troca a CA automaticamente.

A porta padrão é HTTPS 8443, tanto para o painel quanto para a API autenticada dos firewalls. Não existe SSH entre o painel e os agentes. O banco não precisa de nenhuma publicação de porta.
