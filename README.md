# SYNAPSE

**Universal AI Agent Execution & Orchestration Platform**

> *A IA pensa, planeja e decide. O SYNAPSE controla, executa, registra e devolve resultados.*

---

## Status do Projeto

- **Fase 0 (Discovery e Arquitetura):** Concluída, aprovada e publicada no GitHub ([08 — Decisões Arquiteturais](docs/08-decisoes-pendentes.md)).
- **Fase 1 (Core & Auditoria de Segurança):** Concluída, auditada e publicada no GitHub.
- **Fase 2 (WorkspaceLock, File Manager e Git Manager):** Concluída localmente — aguardando revisão para avançar à Fase 3 (Agent Gateway).
- **Repositório oficial:** `https://github.com/SirGusttavo/synapse.git`

## O que está implementado (Fases 1 e 2)

- **Configuração JSON/JSONC validada com Zod** (`src/config/`) com suporte a `.synapse/config.jsonc` e carregamento isolado de `.env` local (`D-02`, `D-03`).
- **Persistência local com `node:sqlite`** (`src/storage/`) e migrations versionadas (`tasks` e `audit_events`).
- **Security Baseline & Revalidação Pré-Mutação** (`src/modules/security/`):
  - `Redactor` centralizado para mascarar tokens/chaves/senhas em textos e objetos;
  - `EnvSanitizer` bloqueando propagação de segredos aos processos filhos (por chave e por padrão de valor);
  - `WorkspaceGuard` impedindo escape do workspace (traversal, junctions NTFS, UNC) e acesso a arquivos sensíveis (`.env`, chaves privadas) ou mutação direta de `.git/`;
  - `CommandAnalyzer` com análise estrutural de comandos, quebras de linha, subexpressões, flags e ofuscação;
  - `PolicyEngine` (*default-deny*, `D-06` com `file.delete` em `HUMAN_APPROVAL`, snapshot imutável congelado, `inputDigest` SHA-256 de uso único e `revalidateAuthorized` imediatamente antes de operações mutáveis).
- **Concorrência Controlada (`WorkspaceLock`)** (`src/modules/task-manager/workspace-lock.ts`):
  - Trava Reader-Writer (RWLock) justa em ordem FIFO por caminho canônico do workspace (leituras simultâneas permitidas; mutações de arquivo, Git e shell estritamente exclusivas).
- **File Manager Tipado (7 ferramentas sem `shell.exec`)** (`src/modules/file-manager/`):
  - `file.list`, `file.read`, `file.create`, `file.edit`, `file.search`, `file.move`, `file.delete` com gravação atômica, detecção de binários e confinamento ao workspace.
- **Git Manager Tipado (13 ferramentas com `shell: false` e contenção de hooks)** (`src/modules/git-manager/`):
  - `git.status`, `git.diff`, `git.log`, `git.branch`, `git.tag`, `git.init`, `git.clone`, `git.checkout`, `git.add`, `git.commit`, `git.pull`, `git.push`, `git.merge`;
  - `GitPreflight` com defesa contra *option injection*, bloqueio de stage/commit de arquivos sensíveis e desativação obrigatória de hooks arbitrários (`-c core.hooksPath=.git/__synapse_disabled_hooks__`, `-c core.fsmonitor=false`, `-c protocol.ext.allow=never`).
- **Auditoria e Logging Estruturado** (`src/modules/audit/`): Pino (JSON com redaction em `stderr`) + trilha append-only em SQLite.
- **CLI desacoplada** (`src/cli/`) consumindo a fachada `SynapseRuntime` (`src/core/runtime.ts`).

---

## Uso Rápido (Fases 1 e 2)

Pré-requisitos: Node.js `>= 22.13.0` (validado em `v26.13.0`), Git e PowerShell no Windows.

```powershell
# Instalar dependências e compilar
npm install
npm run build

# Verificar status do ambiente, shell detectado e as 21 ferramentas registradas
node dist/cli/main.js status

# Operações tipadas de arquivos (sem shell.exec)
node dist/cli/main.js file list
node dist/cli/main.js file read README.md --start-line 1 --end-line 15
node dist/cli/main.js file search "WorkspaceLock" -p src

# Operações tipadas de Git (com shell: false e contenção de hooks)
node dist/cli/main.js git status
node dist/cli/main.js git log -n 5
node dist/cli/main.js git diff

# Executar comando PowerShell autorizado pela allowlist (AUTO)
node dist/cli/main.js exec "Write-Output 'SYNAPSE operacional'"

# Consultar trilha de auditoria persistida no SQLite
node dist/cli/main.js audit
```

### Scripts de Verificação

```powershell
npm run typecheck   # TypeScript strict (src + tests)
npm run lint        # Biome check
npm test            # Vitest (unitários, integração PowerShell/File/Git/CLI e segurança)
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
