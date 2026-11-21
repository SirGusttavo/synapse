# SYNAPSE

**Universal AI Agent Execution & Orchestration Platform**

> *A IA pensa, planeja e decide. O SYNAPSE controla, executa, registra e devolve resultados.*

---

## Status do Projeto

- **Fase 0 (Discovery e Arquitetura):** Concluída e aprovada ([08 — Decisões Arquiteturais](docs/08-decisoes-pendentes.md)).
- **Fase 1 (Core):** Concluída localmente — aguardando revisão para avançar à Fase 2 (Sistema de Arquivos e Git).
- **Repositório oficial:** `https://github.com/SirGusttavo/synapse.git`

## O que está implementado (Fase 1 — Core)

- **Configuração JSON/JSONC validada com Zod** (`src/config/`) com suporte a `.synapse/config.jsonc` e carregamento isolado de `.env` local (D-02, D-03).
- **Persistência local com `node:sqlite`** (`src/storage/`) e migrations versionadas (`tasks` e `audit_events`).
- **Security Baseline ativa desde o início** (`src/modules/security/`):
  - `Redactor` centralizado para mascarar tokens/chaves/senhas em textos e objetos;
  - `EnvSanitizer` bloqueando propagação de segredos aos processos filhos;
  - `WorkspaceGuard` impedindo escape do workspace e acesso a arquivos sensíveis;
  - `CommandAnalyzer` com análise estrutural de comandos, flags, encadeamento e ofuscação;
  - `PolicyEngine` (*default-deny*, D-06 com exclusão de arquivo individual em `HUMAN_APPROVAL`, autorização marcada via `Symbol` exigida pelo `ExecutionEngine`).
- **Auditoria e Logging Estruturado** (`src/modules/audit/`): Pino (JSON com redaction em `stderr`) + trilha append-only em SQLite.
- **Execução Controlada** (`src/modules/execution-engine/`, `src/modules/shell-manager/`, `src/modules/task-manager/`):
  - `NodeProcessRunner` sobre `node:child_process` com **`shell: false`**, truncamento por byte, timeout e encerramento de árvore de processos no Windows (`taskkill /PID /T /F`);
  - `PowerShellAdapter` priorizando `pwsh.exe` com fallback para `powershell.exe`, UTF-8 forçado e propagação fiel de códigos de saída;
  - `TaskManager` com máquina de estados validada e cancelamento via `AbortSignal`.
- **CLI desacoplada** (`src/cli/`) consumindo a fachada `SynapseRuntime` (`src/core/runtime.ts`).

---

## Uso Rápido (Fase 1)

Pré-requisitos: Node.js `>= 22.13.0` (validado em `v26.13.0`) e PowerShell no Windows.

```powershell
# Instalar dependências e compilar
npm install
npm run build

# Verificar status do ambiente, shell detectado e política ativa
node dist/cli/main.js status

# Executar comando PowerShell autorizado pela allowlist (AUTO)
node dist/cli/main.js exec "Write-Output 'SYNAPSE operacional'"

# Testar bloqueio automático de comando destrutivo (DENIED -> exit 126)
node dist/cli/main.js exec "git push --force origin main"

# Consultar trilha de auditoria persistida no SQLite
node dist/cli/main.js audit

# Inspecionar configuração efetiva validada (sem expor segredos)
node dist/cli/main.js config
```

### Scripts de Verificação

```powershell
npm run typecheck   # TypeScript strict (src + tests)
npm run lint        # Biome check
npm test            # Vitest (unitários, integração PowerShell/CLI e segurança)
npm run verify      # typecheck + lint + test
npm run build       # Compilação para dist/
```

---

## Índice da Documentação

| Documento | Conteúdo |
| :--- | :--- |
| [01 — Visão do Produto](docs/01-visao-produto.md) | Problema, proposta de valor, princípios, objetivos, escopo do MVP e não-objetivos |
| [02 — Requisitos Funcionais e Não Funcionais](docs/02-requisitos.md) | Catálogo estruturado de requisitos funcionais (RF) e não funcionais (RNF) |
| [03 — Arquitetura Proposta](docs/03-arquitetura.md) | Arquitetura modular, diagrama de componentes, fluxo agente-executor e estrutura de diretórios |
| [04 — Stack Tecnológica](docs/04-stack-tecnologica.md) | Baseline do ambiente local, avaliação de dependências, licenças e taxonomia de integrações de IA |
| [05 — Segurança e Matriz de Permissões](docs/05-seguranca-permissoes.md) | Defesa em profundidade, matriz de permissões, proteção de credenciais, auditoria e isolamento |
| [06 — Riscos e Limitações](docs/06-riscos-limitacoes.md) | Riscos técnicos, operacionais, de segurança, de custos e limitações conhecidas |
| [07 — Roadmap Técnico e Critérios do MVP](docs/07-roadmap-mvp.md) | Plano em fases (0 a 5), estratégia de segurança incremental e critérios objetivos de aceitação |
| [08 — Decisões Arquiteturais](docs/08-decisoes-pendentes.md) | Registro das decisões aprovadas (D-01 a D-07) |

---

**SYNAPSE — From Intelligence to Action.**
