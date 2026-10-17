# Transição para 0.7.0

A versão 0.7.0 padroniza todos os nomes atuais como O3 Cloud Central:

- Banco e usuário SQL: `o3cloudcentral`.
- Tabelas e índices: prefixo `o3cloudcentral_`.
- Pacote Python: `o3cloudcentral`.
- Dados da central: `/var/lib/o3cloudcentral`.
- Dados, runtime e conta do pfSense: diretórios e usuário `o3cloudcentral`.
- Variáveis de ambiente: prefixo `O3CLOUDCENTRAL_`.
- Protocolos dos agentes e controle local do Windows: identificadores O3 Cloud Central.

## Instalação limpa

Para um laboratório que será descartado, use uma VM nova e o instalador 0.7.0 do README. Refaça os cadastros e instale os agentes novos. A senha inicial é admin/admin, com troca obrigatória.

## Preservar uma central existente

Programe uma janela de manutenção e mantenha seus backups protegidos. Baixe e extraia a distribuição 0.7.0, conferindo o SHA-256. Dentro da pasta extraída:

```bash
sudo python3 deploy/migrate-central.py --plan
sudo python3 deploy/migrate-central.py
```

Para uma instalação anterior ao instalador oficial, revise a origem e use `--adopt-existing` nos dois comandos.

A migração descobre os nomes anteriores a partir da configuração local, confere as 10 tabelas, cria o destino com os nomes atuais e copia os registros dentro do próprio MariaDB. Cada registro é conferido antes da ativação. Senhas, cadastros e a CA são preservados.

Somente após a nova central passar no teste HTTPS são removidos o banco e o usuário SQL anteriores. Em uma falha tratada, a ferramenta tenta restaurar a configuração e o serviço anteriores. O código anterior é mantido para recuperação até a validação.

Não execute simultaneamente alterações no painel. Uma interrupção de energia pode exigir recuperação administrativa: preserve os bancos e `/etc/o3cloudcentral-migration.json` antes de qualquer nova tentativa. A ferramenta recusa sobrescrever um destino já existente.

As versões anteriores dos agentes precisam ser atualizadas ou reinstaladas. Para o pfSense, remova o pacote anterior pela interface de pacotes e gere uma nova instalação no painel. Instale novamente os terminais com os links da versão atual. A migração da central não modifica silenciosamente as máquinas dos clientes.
