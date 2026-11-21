# 05 — Segurança e Matriz de Permissões

## 1. Filosofia de Segurança

No **SYNAPSE**, segurança **não é um módulo cosmético adicionado no final do projeto**: ela é o contrato estrutural que separa uma plataforma de execução confiável de um executor remoto inseguro.

### Princípios Fundamentais
1. **Default Deny (Negação por Padrão):** qualquer ferramenta, caminho, flag ou comando não explicitamente permitido por política é negado ou escalado para aprovação humana.
2. **Defesa em Profundidade:** nunca depender exclusivamente de listas de comandos proibidos (*blocklists* de strings são facilmente contornáveis por aliases do PowerShell, codificação Base64 `-EncodedCommand`, variáveis de ambiente, subexpressões ou encadeamento).
3. **Menor Privilégio:** o SYNAPSE executa sem elevação administrativa (`Run as Administrator`), confinado ao workspace autorizado e com variáveis de ambiente filtradas.
4. **Transparência Auditável:** toda decisão de permissão (automática, aprovada, negada ou bloqueada) gera registro estruturado sem expor segredos.

---

## 2. Pipeline de Validação em 5 Camadas

Toda solicitação originada por um agente passa obrigatoriamente pelas cinco camadas abaixo antes de atingir o sistema operacional:

| Camada | Componente | O que valida |
| :--- | :--- | :--- |
| **1. Contrato** | `Zod Schema Validator` | Verifica tipos, campos obrigatórios, limites de tamanho, ausência de campos inesperados (`strict()`) e formato estruturado dos parâmetros. |
| **2. Fronteira de Workspace** | `WorkspaceGuard` | Normaliza caminhos com `path.resolve`, resolve links simbólicos/junctions com `fs.realpath` (no alvo ou no ancestral existente), verifica case-insensitivity do Windows e bloqueia qualquer escape da raiz autorizada ou acesso a arquivos sensíveis (`.env`, `*.key`, `*.pem`, `~/.ssh`, etc.). |
| **3. Análise Estrutural e de Efeitos** | `CommandAnalyzer` + `GitPreflight` | Inspeciona argumentos e efeitos colaterais: detecta flags destrutivas (`--force`, `--hard`, `-Recurse -Force`), comandos PowerShell ofuscados (`-EncodedCommand`, `Invoke-Expression`/`iex`, `Start-Process -Verb RunAs`), operadores de encadeamento/redirecionamento (`;`, `\|`, `&&`, `>`, `$()`), alteração em lote de múltiplos arquivos e acesso de rede não previsto. |
| **4. Política e Aprovação** | `PolicyEngine` + `ApprovalBroker` | Classifica a operação em `AUTO`, `CONDITIONAL`, `HUMAN_APPROVAL` ou `DENIED`, combinando regras padrão com a configuração do projeto/usuário. Quando necessário, pausa a tarefa e solicita aprovação explícita do operador. |
| **5. Contenção em Runtime** | `ExecutionEngine` + `EnvSanitizer` | Executa com `shell: false` (em ferramentas estruturadas como Git), remove variáveis sensíveis do ambiente do subprocesso, impõe timeout rígido, teto de `stdout`/`stderr` e encerramento completo da árvore de processos no cancelamento/timeout. |

---

## 3. Matriz de Permissões (Política Padrão Configurável)

> **Regra de precedência:** uma regra configurada pelo usuário pode tornar a política **mais restritiva** livremente. Relaxar itens classificados como **BLOQUEADO POR PADRÃO** exige configuração explícita consciente + confirmação humana em tempo de execução (ou permanece desabilitado no perfil padrão de segurança).

### 3.1 Níveis de Permissão

| Nível | Código | Comportamento |
| :--- | :--- | :--- |
| **Automático** | `AUTO` | Executa imediatamente sem interromper o fluxo, mantendo registro completo na auditoria. |
| **Condicional** | `CONDITIONAL` | Avalia critérios contextuais configuráveis (ex.: dentro do workspace, comando na allowlist do projeto, limite de arquivos afetados). Caso os critérios não sejam satisfeitos ou no modo conservador, escala para aprovação humana. |
| **Autorização Humana** | `HUMAN_APPROVAL` | Pausa a tarefa (`AWAITING_APPROVAL`) e exige confirmação explícita do operador humano antes de executar. |
| **Bloqueado por Padrão** | `DENIED` | Rejeitado imediatamente pela `Security Layer`; nunca chega ao `Execution Engine`. |

### 3.2 Matriz Completa por Domínio

| Domínio | Operação | Nível Padrão | Validações e Restrições Adicionais |
| :--- | :--- | :--- | :--- |
| **Git (Leitura)** | `git status`, `git log`, `git diff`, listar branches/tags | `AUTO` | Somente dentro do workspace; `shell: false`; argumentos estruturados. |
| **Git (Local Controlado)** | `git init`, `git branch <nome>`, `git checkout` (sem `--force`), `git add`, `git tag` (criação local) | `CONDITIONAL` | *Pre-flight check* de repositório válido e working tree; rejeita flags destrutivas. |
| **Git (Commit / Integração)** | `git commit`, `git merge`, `git pull`, `git clone` | `CONDITIONAL` | `commit` verifica arquivos staged (bloqueia commit acidental de `.env`/segredos); `clone`/`pull` validam destino dentro do workspace e desabilitam prompt interativo (`GIT_TERMINAL_PROMPT=0`). |
| **Git (Publicação Remota)** | `git push` (normal, sem force) | `HUMAN_APPROVAL` | Sempre exibe remoto, branch local/remota e resumo dos commits a publicar antes da confirmação humana. |
| **Git (Destrutivo)** | `git push --force` / `-f`, `git reset --hard`, `git clean -fd`, reescrita de histórico publicado | `DENIED` | Bloqueado por padrão na política e rejeitado estruturalmente no `GitPreflight`. |
| **Arquivos (Leitura)** | Listar diretórios, ler arquivos permitidos, pesquisar conteúdo | `AUTO` | Confinado ao workspace; bloqueio de arquivos sensíveis (`.env*`, chaves privadas); limite de tamanho. |
| **Arquivos (Escrita)** | Criar arquivo, editar arquivo único dentro do workspace | `AUTO` | Confinado ao workspace; bloqueio de edição de arquivos de configuração sensíveis ou fora do escopo. |
| **Arquivos (Impacto Amplo)** | Mover arquivos, edição/criação em lote de múltiplos arquivos (acima de limiar configurável) | `CONDITIONAL` | Escala para aprovação humana quando excede o limiar ou afeta arquivos críticos. |
| **Arquivos (Exclusão)** | Excluir arquivo individual no workspace | `CONDITIONAL` / `HUMAN_APPROVAL` | Exclusão de arquivo exige autorização; exclusão de diretórios é sempre `HUMAN_APPROVAL`. |
| **Arquivos (Fora do Escopo / Diretórios)** | Exclusão de diretórios; leitura ou escrita fora do workspace autorizado | `HUMAN_APPROVAL` | Exige justificativa e exibição explícita do caminho canônico absoluto; negado se a política do workspace proibir escape. |
| **Arquivos (Destrutivo)** | Exclusão indiscriminada (`rm -rf *`, `Remove-Item -Recurse -Force` em raiz/globs amplos) | `DENIED` | Bloqueado por análise estrutural de alvo e flags. |
| **Shell (Testes e Builds)** | Executar suítes de testes e builds autorizados (ex.: `npm test`, `vitest`, `tsc --noEmit`, scripts declarados na allowlist do projeto) | `AUTO` | Apenas comandos explícitos permitidos na política do workspace, sem encadeamento malicioso ou redirecionamento externo. |
| **Shell (Dependências e Scripts)** | Instalar dependências (`npm install`, etc.), executar scripts externos/locais não listados na allowlist, comandos shell arbitrários | `CONDITIONAL` | Instalações e scripts externos escalam para aprovação exibindo comando exato e pacotes/alvos quando identificáveis. |
| **Configurações** | Alterar configurações do projeto (ex.: `package.json`, `tsconfig.json`) | `CONDITIONAL` | Exibe diff/alvo da alteração; arquivos sensíveis (políticas de segurança do próprio SYNAPSE, `.git/config`, hooks) exigem `HUMAN_APPROVAL`. |
| **Sistema / Admin** | Operações administrativas, alteração de variáveis globais/registro, alteração em configurações sensíveis do sistema | `HUMAN_APPROVAL` | Exige aprovação explícita; elevação privilegiada sem justificativa permanece `DENIED`. |
| **Privilégios e Credenciais** | Execução privilegiada (`RunAs`, `sudo`, `gsudo`), acesso não autorizado a credenciais, leitura de variáveis secretas, exfiltração de tokens | `DENIED` | Bloqueado por padrão e reforçado por `EnvSanitizer` + regras de arquivos sensíveis. |

---

## 4. Protocolo de Aprovação Humana

Quando o `PolicyEngine` retorna `HUMAN_APPROVAL` (ou `CONDITIONAL` que requer confirmação), o `ApprovalBroker` envia um `ApprovalRequest` estruturado para o `IApprovalHandler` ativo (na CLI no MVP):

1. **Contexto mínimo obrigatório apresentado ao operador:**
   - Identificador da tarefa e do agente/modelo solicitante;
   - Ferramenta e operação exata (comando ou argumentos sanitizados);
   - Diretório de trabalho canônico (`cwd`) e caminhos afetados;
   - Classificação de risco e motivo pelo qual a aprovação foi solicitada;
   - Efeitos colaterais esperados (ex.: gravação em disco, operação de rede, alteração de histórico Git).
2. **Escopo da decisão:**
   - Padrão seguro: **aprovação única** (*allow once*) para aquela solicitação específica.
   - Negação (*deny*) permite opcionalmente informar um motivo curto que é repassado ao agente para orientar uma alternativa segura.
   - Sem modo "aprovar tudo irrestritamente" por padrão.
3. **Timeout de aprovação:**
   - Se a aprovação expirar (quando configurado em modo não-interativo) ou o processo receber `SIGINT`, a operação é tratada como `DENIED`/`CANCELLED` (*fail-closed*).

---

## 5. Proteção de Credenciais e Auditoria

### 5.1 Gestão de Credenciais (Segredos)
- **Separação de ambientes:** subprocessos executados pelo `Execution Engine` recebem uma lista filtrada de variáveis de ambiente (*env scrubbing*). Variáveis como `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GITHUB_TOKEN`, `GH_TOKEN`, `AWS_*`, `SYNAPSE_*_KEY` e quaisquer chaves cadastradas como sensíveis são **removidas** do ambiente filho por padrão.
- **Armazenamento:** no MVP, chaves de API são carregadas de variáveis de ambiente locais do processo pai do SYNAPSE (ou cofre do SO na Fase 4 — ver Decisão Pendente D-03) e **nunca** gravadas em arquivos de configuração versionados no repositório.
- **Bloqueio de leitura acidental:** o `File Manager` bloqueia leitura de `.env`, `.env.*` (exceto `.env.example`), `*.pem`, `*.key`, `id_rsa`, `id_ed25519` e diretórios de credenciais de sistema.

### 5.2 Sanitização (*Redaction*) e Trilha de Auditoria
- **Redaction dupla:**
  1. **Por chave estrutural:** propriedades chamadas `password`, `token`, `secret`, `apiKey`, `authorization`, `cookie`, `credential` são substituídas por `[REDACTED]`.
  2. **Por padrão de conteúdo:** regex aplicadas sobre `stdout`, `stderr`, argumentos e mensagens de erro mascaram tokens conhecidos (`sk-*`, `sk-ant-*`, `ghp_*`, `github_pat_*`, `AIza*`, `Bearer *`, URLs com `user:pass@`).
- **Campos mínimos registrados em `audit_events` (SQLite):**
  - `id`, `timestamp_utc`, `session_id`, `task_id`
  - `actor` (agente/provedor/modelo ou operador CLI)
  - `operation` (nome da ferramenta e categoria)
  - `command_or_args_sanitized` (JSON sanitizado)
  - `working_directory`
  - `policy_level` e `policy_decision`
  - `approval_status` (`not_required`, `approved`, `denied`, `timed_out`)
  - `exit_code`, `duration_ms`, `status`
  - `error_summary` (sanitizado)

---

## 6. Isolamento, Limites de Recursos e Caminho para Sandboxes

### No MVP (Windows Local)
- Confinamento lógico de workspace (`WorkspaceGuard`) + validação estrutural de comandos (`CommandAnalyzer`).
- Limites determinísticos por tarefa: `timeoutMs`, `maxOutputBytes`, `maxFileSizeBytes`, `maxAgentSteps`.
- Encerramento garantido de árvore de processos no Windows (`taskkill /PID <pid> /T /F` quando `abort`/timeout disparar) para evitar processos filhos órfãos.
- *Limitação honesta:* comandos shell autorizados executam sob o mesmo usuário do Windows que iniciou o SYNAPSE; portanto, validação prévia e aprovação humana são barreiras reais necessárias no MVP, não dispensáveis.

### Evolução Futura (Fase 5 — Sandboxing Real)
A interface `IProcessRunner` é desenhada para permitir plugar executores isolados no futuro sem reescrever `Execution Engine` ou `Agent Gateway`:
- **Containers (Docker / Podman)** montando apenas o workspace como volume com rede desabilitada por padrão;
- **Windows Job Objects / AppContainer** para limites rígidos de CPU/memória/processos no Windows;
- **WSL2 / MicroVMs** para tarefas de alto risco ou execução de código não confiável.
