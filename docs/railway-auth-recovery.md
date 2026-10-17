# Railway MCP — recuperação da sessão Google por link (em desenvolvimento)

## Objetivo

Quando uma operação do MCP falhar com `AUTH`, o agente deve obter um link de recuperação e apresentá-lo à pessoa usuária. O navegador deve permitir a recuperação sem copiar tokens no chat, sem abrir o terminal do Railway e sem desabilitar as proteções do Windows.

**O fluxo completo de login remoto do Google ainda não está implementado.** A primeira etapa, nesta branch, permite importar pelo navegador um `storage_state.json` previamente gerado no computador. Isso resolve a transferência pontual sem Base64 nem PowerShell, mas **não** atende por si só ao requisito de novo login direto no link.

## O que existe nesta branch

- Ferramenta `auth_recovery_link` geradora de link HTTPS assinado com validade de cinco minutos.
- Página `GET /auth/recover/{token}` para selecionar o arquivo de sessão.
- `POST` limitado a 1 MiB, com verificação de origem, token de uso único, perfil e e-mail da conta esperada.
- Teste de sessão contra Google antes de substituir `storage_state.json`, gravação atômica e tentativa de reabertura do cliente MCP.
- Nenhuma rota ou ferramenta exposta por padrão. A ativação é explícita e requer URL pública HTTPS e conta fixa.
- Nenhuma senha, cookie ou token é solicitado no chat.

## Ativação no Railway (somente depois de revisão, teste e deploy)

Variáveis de ambiente no serviço HTTP existente:

```text
NOTEBOOKLM_MCP_REAUTH_LINKS=1
NOTEBOOKLM_MCP_EXPECTED_GOOGLE_ACCOUNT=<conta-do-notebooklm>
NOTEBOOKLM_MCP_PUBLIC_URL=https://<dominio-oficial-do-servico>
```

O serviço deve continuar protegido pelo OAuth/bearer já configurado para o MCP. A ferramenta assina o link no contexto de uma chamada MCP autenticada. **Não coloque o arquivo de sessão ou o master token em variáveis publicadas ou logs.**

O ChatGPT deverá chamar `auth_recovery_link` depois de receber um erro `AUTH` e abrir o endereço retornado ao usuário. O MCP não consegue abrir uma janela no dispositivo por conta própria; a experiência depende de um link clicável apresentado pelo cliente.

## Fase pendente — login Google 100% pelo navegador

O retorno desejado é: ChatGPT → MCP detecta expiração → link de recuperação → navegação Google dentro de uma sessão de navegador hospedada no Railway → confirmação → gravação no mesmo volume persistente → repetição da chamada MCP.

Um redirecionamento comum para `accounts.google.com` **não** transfere os cookies `HttpOnly` do navegador local ao servidor Railway. Será necessário validar uma sessão de navegador *remota* controlada pelo serviço. O Google pode bloquear autenticação automatizada em ambiente de nuvem, portanto não é correto prometer esse fluxo até um teste real.

Critérios de aceitação da fase remota:

1. O login deve acontecer somente em uma sessão remota com origem HTTPS própria, com token temporário e autorizado pelo MCP; jamais solicitar senha Google em formulário desenvolvido por nós.
2. Tokens expiram em poucos minutos, são de uso único, com limite de tentativas, isolamento por usuário/conta e sem URLs sensíveis em logs.
3. O navegador remoto deve exibir a própria página oficial do Google e permitir 2FA; não copiar cookies de um navegador pessoal por JavaScript (não é possível).
4. Cookies salvos exclusivamente no volume persistente do Railway, com permissões restritas, e testados contra Google antes da substituição.
5. O MCP reabre a sessão sem redeploy e volta a servir os cadernos; se o Google rejeitar o login no ambiente remoto, a UI oferece alternativa segura e explica a limitação.
6. Avaliar memória e CPU do Chromium no plano Railway antes de habilitar. Não iniciar navegadores a cada consulta, somente em fluxo de recuperação.
7. Testes de autorização, concorrência, Replay/TTL, limite de tamanho, falhas Google, volume persistente, e recuperação após reinício do serviço.

## Limitações e riscos

- O protocolo usado para o NotebookLM pessoal é não oficial, com sessões Google que podem expirar ou ser revogadas.
- O arquivo `storage_state.json` é uma credencial sensível. O link de recuperação dá poder temporário de substituí-lo; não compartilhar o endereço.
- O OAuth usado para conectar ChatGPT ao MCP é **separado** da sessão Google usada pelo NotebookLM.
- Esta branch fica em PR **draft**, sem merge ou deploy automático até validação da segurança e do fluxo de login remoto.
