# O3 Cloud Central

<img src="assets/O3CloudCentral.png" alt="O3 Cloud" width="160">

O **O3 Cloud Central** permite que computadores autorizados acessem serviços de um cliente através do pfSense dele. A central reúne os clientes, serviços, permissões e estados em um painel web.

O terminal não precisa de uma VPN com acesso à rede inteira. O agente abre portas locais apenas para os serviços autorizados, como uma aplicação web, SSH ou um banco de dados TCP.

## Como funciona

```text
Windows / Debian / Ubuntu
         │ uma porta TCP por cliente (instalação, controle e túnel)
         ▼
    pfSense do cliente ─────► serviços internos autorizados
         │ HTTPS de saída, com autenticação do agente
         ▼
    O3 Cloud Central ───────► MariaDB local
         ▲
    administrador via navegador, LAN ou VPN
```

- **Central:** cadastra clientes e serviços, distribui permissões e mostra telemetria. É escrita em Python e usa MariaDB.
- **pfSense:** autentica os terminais, aplica permissões, encaminha os acessos e envia hostname, IP, sistema operacional e estado dos terminais para a central.
- **Terminal:** instala sua própria identidade, conecta ao pfSense e cria os endereços locais exibidos no painel.

Os terminais se comunicam com o pfSense do cliente. Eles não precisam acessar diretamente a central. O pfSense precisa alcançar a URL HTTPS da central. O painel pode ficar acessível apenas pela rede interna/VPN; publicar a central na Internet é opcional.

## Instalar a central no Ubuntu

Use uma **VM dedicada Ubuntu Server 24.04 ou 26.04 LTS, amd64**, com systemd, acesso à Internet para baixar os pacotes e um IP ou DNS estável. Como ponto de partida para um piloto: 2 vCPU, 2 GB de RAM e 20 GB de disco; o dimensionamento definitivo depende da quantidade de clientes e acessos.

Escolha a URL que os pfSenses e administradores realmente alcançarão. Exemplo interno: `https://10.20.0.10:8443`. Se usar DNS, configure a resolução antes.

Baixe o instalador e execute, substituindo a URL:

```bash
curl --fail --location --proto '=https' --proto-redir '=https' \
  https://raw.githubusercontent.com/Qu4dr4d0/o3-cloud-central/v0.7.3/install.sh \
  -o /tmp/o3cloudcentral-install.sh
sudo sh /tmp/o3cloudcentral-install.sh --url https://10.20.0.10:8443
```

Novas instalações usam a conta de sistema `_o3cloudcentral`, sem login, separada da conta usada para acessar a VM por SSH. O nome do banco continua `o3cloudcentral`.

O instalador confere o SHA-256 da distribuição, instala MariaDB e o ambiente Python com dependências fixadas, cria um usuário de serviço, gera certificados exclusivos e inicia a central com systemd. Os agentes genéricos Windows, Linux e pfSense já vêm incluídos. Não é necessário compilar na VM.

Ele não cria redirecionamentos, não altera SSH e não modifica as regras do firewall. Também recusa adotar automaticamente banco, usuário ou diretórios de uma instalação desconhecida.

### Primeiro acesso

1. Abra a URL escolhida no navegador.
2. O certificado é emitido pela CA própria desta instalação. Copie **somente** `/etc/o3cloudcentral/ca.crt` pelo seu acesso administrativo seguro e importe-o como autoridade confiável nos computadores dos administradores. Nunca distribua `ca.key` ou `server.key`.
3. Entre com usuário **`admin`** e senha **`admin`**.
4. A central exige uma nova senha, com pelo menos 12 caracteres, antes de liberar o painel. Essa exigência também é aplicada no backend; a senha inicial não permite gerenciar clientes nem criar usuários.
5. Para criar outros usuários, clique no seu nome no canto superior direito e escolha **Criar usuário**.

A senha padrão vale somente para uma instalação nova. Atualizar não redefine senhas. Nesta versão, todos os usuários do painel têm acesso administrativo.

## Regras de rede

| Comunicação | Regra necessária |
|---|---|
| Administrador → central | Permitir TCP 8443, ou a porta escolhida, pela LAN/VPN |
| pfSense do cliente → central | Permitir saída para a URL/porta HTTPS da central |
| Terminal → pfSense do cliente | Permitir a porta TCP configurada no agente, por exemplo 2222 |
| pfSense → serviço interno | Permitir o IP e a porta de destino do serviço |
| MariaDB | Somente local, por socket Unix; não publicar TCP 3306 |

Se o pfSense do cliente estiver atrás de outro firewall, faça **um redirecionamento TCP por cliente**. Exemplo: `gateway.example.com:2223 → WAN do pfSense 10.20.0.21:2222`. No pfSense de destino, permita TCP na WAN, destino **WAN address**, porta **2222**. O firewall que faz o NAT também precisa permitir o tráfego encaminhado; use a regra associada ao redirecionamento.

Essa porta é do agente O3 Cloud Central, não do SSH administrativo nem da interface web do pfSense. Clientes diferentes podem usar portas externas diferentes apontando para a mesma porta interna de seus respectivos pfSenses.

## Cadastrar um cliente e instalar no pfSense

No painel, clique em **Cadastrar cliente** e preencha:

| Campo | Exemplo | Significado |
|---|---|---|
| Nome | Filial Centro | Nome para identificar o cliente |
| Endereço público | `gateway.example.com:2223` | DNS/IP e porta que os terminais alcançarão |
| Endereço de escuta | `10.20.0.21:2222` | IP da interface do próprio pfSense e porta interna em que o agente recebe as conexões |
| Redes dos serviços | `172.30.20.0/24` | Redes em que os serviços deste cliente podem ser cadastrados |

O endereço de escuta exige **IP e porta**. Ele não é o endereço da central.

No lápis ao lado do endereço público, use **Editar cliente** para alterar o endereço e as **redes internas autorizadas**. Informe as redes com máscara, separadas por vírgula. Para retirar uma rede, remova antes os serviços que dependem dela ou mantenha outra rede que cubra os seus destinos.

1. Copie o comando gerado e execute como root no console ou em **Diagnostics → Command Prompt** do pfSense.
2. Use **pfSense CE 2.7.x, 2.8.x ou 2.9.x, amd64** (bases FreeBSD 14, 15 e 16). O mesmo comando atende essas versões; o runtime Python e as bibliotecas de compatibilidade ficam isolados, sem modificar os repositórios ou as bibliotecas do firewall.
3. Confira o estado no painel. No pfSense, há uma página em **Services → O3 Cloud Central**.
4. Para remover, use **System → Package Manager → Installed Packages**, localize **O3 Cloud Central** e clique na lixeira. O pacote remove os seus processos, identidades e arquivos sem remover regras ou serviços administrativos que não pertençam a ele.
5. Se precisar instalar o mesmo cliente novamente, use **Gerar nova instalação** no painel. O fluxo substitui a identidade antiga; leia a confirmação, pois terminais vinculados ao túnel anterior podem precisar de reinstalação.

Os comandos de instalação do pfSense são específicos para cada cliente. Nunca reutilize a configuração ou identidade de um firewall em outro.

## Instalar os terminais

1. Cadastre os serviços do cliente: nome, IP interno, porta e tipo.
2. Em **Terminais → Instalar terminais**, escolha **Windows** ou **Debian / Ubuntu** e os serviços permitidos.
3. Gere e entregue o link ao TI do cliente. O mesmo link pode ser usado em várias máquinas.
4. Cada instalação gera uma identidade própria e aparece automaticamente na central, com hostname, IP local e sistema operacional. Não é necessário cadastrar cada terminal antes.
5. Revogar o link impede novas instalações por ele; **Remover acesso** revoga uma máquina já instalada. São ações diferentes.

O link contém uma credencial de cadastro: compartilhe apenas com o TI autorizado. Gerar um novo link do mesmo sistema invalida o anterior; o link do outro sistema e as máquinas já instaladas permanecem válidos.

### Windows

Execute o instalador baixado como administrador. Ele oferece o atalho da área de trabalho, adiciona o aplicativo ao menu Iniciar, instala o serviço e o ícone junto ao relógio. O ícone fica vermelho quando desconectado. A conexão é iniciada automaticamente com o Windows, mesmo que a pessoa tenha desconectado antes.

Para remover: **Configurações → Aplicativos instalados** ou `appwiz.cpl` → **O3 Cloud Central**. O instalador ainda não possui assinatura Authenticode.

### Debian / Ubuntu

Use Linux **amd64/x86_64, glibc 2.28 ou posterior, com systemd**. Copie o comando apresentado pelo painel e execute como root, ou com `sudo` conforme indicado. O runtime Python do agente já vem no pacote.

Depois de instalado, a linha do terminal Linux na central mostra **Comandos**, com os comandos prontos para copiar:

| Ação | Comando |
|---|---|
| Estado | `sudo o3cloudcentral-agent status` |
| Conectar | `sudo o3cloudcentral-agent start` |
| Parar | `sudo o3cloudcentral-agent stop` |
| Reconectar | `sudo o3cloudcentral-agent restart` |
| Últimos registros | `sudo o3cloudcentral-agent log` |
| Remover | `sudo o3cloudcentral-agent uninstall` |
| Ajuda | `o3cloudcentral-agent help` |

O comando correto é **`uninstall`**. Parar é temporário: o serviço volta a iniciar com o sistema. A desinstalação local remove o agente, mas mantém o registro na central até você remover o acesso pelo painel.

### Acessar os serviços

Use na aplicação do terminal o endereço local exibido no painel, por exemplo `http://127.0.0.1:18080/`. Esse endereço funciona na máquina em que o agente está instalado e autorizado. Não é um link público da central.

## Atualizar, verificar e cuidar dos dados

A transição para 0.7.0 muda banco, caminhos e protocolos dos agentes. Para uma instalação anterior, siga o [guia de migração](deploy/MIGRATION.md) ou use uma VM nova. Atualize ou reinstale também os agentes dos pfSenses e terminais.

Para atualizar uma instalação criada por este instalador, baixe o `install.sh` da versão desejada e execute com a **mesma URL** e `--upgrade`. Os cadastros, senhas e a CA existente são preservados.

```bash
sudo sh /tmp/o3cloudcentral-install.sh --url https://10.20.0.10:8443 --upgrade
sudo systemctl status o3cloudcentral
sudo journalctl -u o3cloudcentral -n 100 --no-pager
```

Atualizar a central não instala silenciosamente uma nova versão nos firewalls ou terminais.

Antes de uma mudança, mantenha backup consistente do banco `o3cloudcentral`, de `/var/lib/o3cloudcentral` (inclui a CA e identidades), `/etc/o3cloudcentral.env` e `/etc/o3cloudcentral-install.json`. Proteja e teste seus backups em ambiente separado. Perder a CA pode exigir reinstalar os agentes. O instalador não configura backup externo automático.

Se a central ficar indisponível, o pfSense pode continuar operando com a política previamente recebida. Alterações e revogações pendentes dependem da comunicação com a central; para interromper imediatamente um cliente isolado, desative/remova o agente no próprio pfSense.

Consulte [instalação e recuperação](deploy/INSTALL.md) e [pacote pfSense](deploy/PFSENSE-NATIVE.md).

## Código e distribuição

O código está em `python/o3cloudcentral`, a interface em `web` e os instaladores em `deploy`. O banco de produção é MariaDB; a camada SQL é compatível com MySQL. Não há SQLite ou arquivo JSON como banco alternativo.

As releases incluem uma distribuição pronta para instalar. O repositório não inclui bancos, senhas, chaves privadas ou configurações de clientes. Para reproduzir os artefatos: [guia de build](deploy/BUILD.md). Dependências de terceiros e suas licenças estão em [THIRD_PARTY_NOTICES.txt](THIRD_PARTY_NOTICES.txt).

Esta publicação é destinada à implantação piloto. Não há MFA nem separação de perfis de acesso nesta versão. O código está público; uma licença própria de redistribuição do projeto ainda não foi definida.
