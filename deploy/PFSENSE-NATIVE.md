# Pacote pfSense 0.7.0

A instalação inicial continua pelo comando gerado ao cadastrar o cliente na central.
O pacote inclui seu próprio runtime Python em `/usr/local/libexec/o3cloudcentral`.
Não altera os repositórios, o Python do sistema, as regras ou o SSH administrativo.

Após instalar:

- **Services → O3 Cloud Central**: estado do processo, iniciar, parar e reiniciar.
- **Status → Services**: controle pelo serviço `o3cloudcentral`.
- **System → Package Manager → Installed Packages**: lixeira do pacote
  `pfSense-pkg-O3CloudCentral` para remover arquivos, identidade, cache e processos.

Remover o pacote mantém o cadastro na central. O firewall deixa de enviar contatos
e passa a ficar sem contato no painel. Excluir o cliente na central é outra operação.
A parada pelo botão Services mantém os dados locais e o serviço volta no próximo boot.

As chaves privadas e os tokens não são exibidos pela página do pacote. Os controles
usam autenticação e proteção CSRF do pfSense. Sinais são enviados somente após
confirmar a linha de comando exata dos processos do produto, nunca para todo Python.

O bootstrap aplica a anotação `repository=pfSense` somente ao registro deste pacote,
após `pkg add`: o pfSense 2.7.2 usa esse campo para exibir Installed Packages.
Isso não configura repositório e não significa que este pacote privado foi publicado
ou certificado pela Netgate. Atualizações continuam sendo fornecidas pela central.

A limpeza de dados acontece no POST-DEINSTALL incorporado ao pacote, após confirmar
uma remoção pela interface nativa. Atualização, reinstalação, recuperação e contextos
desconhecidos preservam a identidade. O POST-DEINSTALL não consulta nem modifica o
banco de pacotes, que ainda está bloqueado durante essa etapa.

O helper universal de emergência permanece disponível para manutenção administrativa.
Uma instalação anterior ao 0.6.2 precisa receber o novo pacote para ter os menus e
os hooks nativos; atualizar somente a central não modifica o firewall.

Alvo validado: pfSense CE 2.7.2, FreeBSD 14, amd64.

## Nova instalação do mesmo cliente

O botão **Gerar nova instalação** usa um cadastro temporário de reinstalação.
Gerar o comando preserva a conexão atual; somente executá-lo substitui a instalação.
O pacote é baixado e verificado antes da limpeza, e seu helper valida o ID do cliente
sob o lock local antes de encerrar o agente. Outro cliente não é removido.
A instalação nova usa outra chave do túnel. Serviços, permissões e cadastros de
terminais permanecem, mas os terminais antigos precisam ser reinstalados para
reconhecer a nova identidade. O aviso aparece na janela do comando.
