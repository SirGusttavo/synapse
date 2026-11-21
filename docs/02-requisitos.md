# 02 — Análise de Requisitos Funcionais e Não Funcionais

Este documento consolida os requisitos derivados diretamente da visão do produto e da especificação dos módulos do **SYNAPSE**. Pontos não definidos pelo escopo inicial são registrados explicitamente em [08 — Decisões Pendentes](08-decisoes-pendentes.md) em vez de serem assumidos arbitrariamente.

---

## 1. Convenções de Classificação

- **MVP:** obrigatório para considerar o MVP funcional (Fases 1 a 4).
- **Pós-MVP:** planejado para expansão (Fase 5+), mas cujo ponto de extensão deve ser preservado pela arquitetura desde o início.

---

## 2. Requisitos Funcionais (RF)

### 2.1 Agent Gateway (Comunicação com Provedores de IA)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-01** | O sistema deve definir uma interface padronizada de provedor de IA (`IAgentProvider`) que normalize prompts, histórico de mensagens, definições de ferramentas (*tool schemas*) e respostas. | MVP |
| **RF-02** | O sistema deve gerenciar sessões de conversação com agentes, mantendo contexto entre turnos e persistindo metadados/histórico localmente. | MVP |
| **RF-03** | O sistema deve interpretar chamadas de ferramentas (*tool calling*) retornadas pelo modelo, validar sua estrutura e devolver o resultado real da execução ao agente para continuidade do ciclo. | MVP |
| **RF-04** | O sistema deve tratar erros de rede, limites de taxa (*rate limits*), respostas malformadas e timeouts na comunicação com provedores de IA. | MVP |
| **RF-05** | O sistema deve permitir registrar um provedor inicial no MVP e adicionar novos provedores (Anthropic, OpenAI, Google Gemini ou compatíveis) sem alterar o núcleo de execução ou orquestração. | MVP (1º provedor + contrato extensível) / Pós-MVP (demais provedores) |

### 2.2 Execution Engine (Núcleo de Execução)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-06** | O `Execution Engine` deve receber somente solicitações previamente autorizadas pela camada de segurança e validadas por schema. | MVP |
| **RF-07** | O sistema deve encaminhar cada operação ao executor especializado correspondente (Shell, File, Git ou ferramenta registrada). | MVP |
| **RF-08** | O sistema deve controlar o tempo máximo de execução (*timeout*) de cada operação, encerrando o processo e seus processos filhos quando o limite for excedido. | MVP |
| **RF-09** | O sistema deve capturar `stdout`, `stderr`, código de saída (*exit code*), duração e estado final (`completed`, `failed`, `timed_out`, `cancelled`) em formato padronizado. | MVP |
| **RF-10** | O sistema deve suportar cancelamento explícito de operações em andamento, garantindo encerramento limpo da árvore de processos. | MVP |

### 2.3 Shell Manager (Integração com Shells)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-11** | O sistema deve isolar a integração de shells atrás de uma abstração (`IShellAdapter`), sem acoplar lógica específica de shell ao `Execution Engine`. | MVP |
| **RF-12** | O sistema deve prover suporte prioritário a **PowerShell no Windows** (`pwsh` 7+ e compatibilidade controlada com Windows PowerShell 5.1 quando aplicável), com execução não-interativa, encoding UTF-8 consistente e propagação fiel de código de saída. | MVP |
| **RF-13** | A arquitetura deve permitir adicionar adaptadores para Bash, Zsh e outros shells compatíveis sem alterar os demais módulos. | Pós-MVP (contrato no MVP) |

### 2.4 File Manager (Gerenciamento de Arquivos e Diretórios)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-14** | O sistema deve suportar operações estruturadas sobre arquivos dentro do workspace autorizado: listar diretórios, ler arquivos, criar arquivos, editar arquivos, pesquisar conteúdo e mover arquivos. | MVP |
| **RF-15** | O sistema deve permitir exclusão de arquivos/diretórios somente mediante validação de política e autorização correspondente. | MVP |
| **RF-16** | O `File Manager` deve restringir todas as operações ao escopo do workspace autorizado, bloqueando travessia de diretórios (`..`), caminhos absolutos fora da raiz e links simbólicos/junctions apontando para fora do workspace (salvo autorização humana explícita onde previsto em política). | MVP |

### 2.5 Git Manager (Gerenciamento de Versionamento)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-17** | O sistema deve oferecer operações Git de leitura: `status`, `diff`, `log` e listagem de `branch` e `tag`. | MVP |
| **RF-18** | O sistema deve oferecer operações Git de ciclo de trabalho controlado: `init`, `clone`, `branch` (criação), `checkout`, `add`, `commit`, `pull`, `push`, `merge` e `tag` (criação). | MVP |
| **RF-19** | O `Git Manager` deve executar verificações prévias (*pre-flight checks*) antes de qualquer operação capaz de alterar histórico ou publicar mudanças (ex.: verificar se o diretório é um repositório válido, detectar branch atual, inspecionar estado do working tree e bloquear flags destrutivas proibidas por padrão como `--force` e `--hard`). | MVP |

### 2.6 Security Layer (Segurança, Permissões e Aprovações)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-20** | O sistema deve implementar uma política de permissões configurável com quatro classificações: **Automático**, **Condicional**, **Autorização Humana** e **Bloqueado por Padrão**. | MVP |
| **RF-21** | O sistema deve validar não apenas o nome do comando/ferramenta, mas também seus argumentos, caminhos resolvidos, processos alvo e potenciais efeitos colaterais antes da execução. | MVP |
| **RF-22** | Quando uma operação exigir aprovação (Condicional ou Autorização Humana), o sistema deve pausar a execução, apresentar contexto claro ao operador (ação, argumentos, diretório, impacto) e aguardar decisão explícita (aprovar ou negar). | MVP |
| **RF-23** | O sistema deve impedir acesso não autorizado a credenciais, segredos e arquivos sensíveis, removendo variáveis de ambiente sensíveis dos processos filhos executados em nome do agente. | MVP |
| **RF-24** | O sistema deve bloquear por padrão operações destrutivas críticas (`git push --force`, `git reset --hard`, exclusão indiscriminada de arquivos e execução privilegiada sem justificativa). | MVP |

### 2.7 Task Manager (Orquestração de Tarefas)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-25** | O sistema deve criar tarefas com identificadores únicos e manter máquina de estados explícita durante todo o ciclo de vida (`PENDING`, `AWAITING_APPROVAL`, `RUNNING`, `COMPLETED`, `FAILED`, `DENIED`, `CANCELLED`, `TIMED_OUT`). | MVP |
| **RF-26** | O sistema deve rastrear tarefas pendentes, em execução e finalizadas, permitindo consulta de status e cancelamento sob demanda. | MVP |
| **RF-27** | O sistema deve evitar conflitos entre operações concorrentes no mesmo workspace (ex.: serializar operações mutáveis de Git e escrita de arquivos por recurso/workspace). | MVP |

### 2.8 Audit Logger (Auditoria e Rastreabilidade)

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-28** | O sistema deve registrar para cada operação: agente responsável, sessão/tarefa, operação solicitada, comando/parâmetros sanitizados, diretório de trabalho, timestamp, decisão de segurança/aprovação concedida, resultado, código de saída e erros encontrados. | MVP |
| **RF-29** | O sistema deve aplicar sanitização (*redaction*) automática para garantir que senhas, tokens, chaves de API e outros conteúdos sensíveis nunca sejam gravados em logs ou banco de auditoria. | MVP |
| **RF-30** | O sistema deve permitir consultar o histórico de operações registradas via CLI. | MVP |

### 2.9 Interface Inicial (CLI) e Extensibilidade

| ID | Requisito | Escopo |
| :--- | :--- | :--- |
| **RF-31** | O sistema deve fornecer uma CLI funcional e consistente para iniciar sessões com agentes, executar/acompanhar tarefas, aprovar/negar operações sensíveis, consultar histórico de auditoria e gerenciar configurações básicas. | MVP |
| **RF-32** | A CLI deve consumir o núcleo exclusivamente por meio de interfaces de serviço desacopladas, permitindo adicionar interface gráfica ou API futura sem duplicar regras de negócio. | MVP |
| **RF-33** | O sistema deve permitir expansão futura por plugins, múltiplos agentes, novos provedores, integração GitHub API e execução remota/sandbox. | Pós-MVP |

---

## 3. Requisitos Não Funcionais (RNF)

### 3.1 Segurança

| ID | Categoria | Requisito | Critério de Verificação |
| :--- | :--- | :--- | :--- |
| **RNF-01** | Menor Privilégio | Nenhuma operação deve ser executada com privilégios elevados por padrão ou fora das permissões configuradas. | Testes automatizados confirmando recusa por padrão (*deny-by-default*) para operações desconhecidas ou fora do workspace. |
| **RNF-02** | Proteção contra Injeção | Execuções estruturadas (ex.: Git) devem invocar binários com `shell: false` e array de argumentos validados por schema, evitando interpolação em string de shell. | Revisão de código + testes adversariais com metacaracteres (`;`, `&&`, `|`, `$()`, `` ` ``). |
| **RNF-03** | Sigilo de Credenciais | Segredos configurados (API keys, tokens) não devem aparecer em `stdout`, `stderr`, logs Pino, banco SQLite ou prompts devolvidos acidentalmente ao agente. | Testes unitários e de integração verificando redaction e filtragem de `process.env` em subprocessos. |
| **RNF-04** | Isolamento Progressivo | A arquitetura de execução deve suportar limites de recursos (timeout, tamanho de saída) no MVP e evoluir para mecanismos de sandbox (containers/processos isolados) sem reescrita do núcleo. | Interface `IProcessRunner` / `ExecutionEngine` isolada de detalhes de sandbox. |

### 3.2 Confiabilidade e Resiliência

| ID | Categoria | Requisito | Critério de Verificação |
| :--- | :--- | :--- | :--- |
| **RNF-05** | Previsibilidade | Falhas em ferramentas, comandos ou provedores de IA devem produzir erros tipados e estruturados, sem derrubar o processo principal do SYNAPSE. | Testes simulando crash de subprocesso, timeout, HTTP 429/500 e JSON inválido do modelo. |
| **RNF-06** | Integridade de Processos | Cancelamentos e timeouts no Windows devem encerrar toda a árvore de processos filhos, evitando processos órfãos mantendo locks de arquivo. | Testes de integração no Windows com subprocesso que gera filhos e verificação de encerramento. |
| **RNF-07** | Integridade de Auditoria | Falhas na gravação de auditoria crítica devem ser detectáveis e tratadas explicitamente (não descartadas silenciosamente). | Testes simulando erro de escrita no storage de auditoria. |

### 3.3 Desempenho e Limites de Recursos

| ID | Categoria | Requisito | Critério de Verificação |
| :--- | :--- | :--- | :--- |
| **RNF-08** | Controle de Memória e Contexto | Saídas `stdout`/`stderr` e leituras de arquivos devem respeitar limites configuráveis de tamanho com truncamento explícito e informativo, protegendo tanto a RAM local quanto a janela de contexto da IA. | Testes com saídas grandes validando teto de bytes e metadado `truncated: true`. |
| **RNF-09** | Baixa Sobrecarga Local | A camada de orquestração e validação local não deve introduzir latência perceptível desnecessária (alvo: validação de política e despacho local em dezenas de milissegundos, excluindo I/O do comando/API). | Medição em testes de integração e benchmarks simples na Fase 1/4. |

### 3.4 Portabilidade e Compatibilidade

| ID | Categoria | Requisito | Critério de Verificação |
| :--- | :--- | :--- | :--- |
| **RNF-10** | Portabilidade Multiplataforma | O núcleo (`core`, `security`, `tasks`, `gateway`, `audit`, `files`, `git`) deve evitar dependência direta de APIs exclusivas do Windows, usando `node:path`, `node:fs` e adaptadores específicos de SO/shell. | Separação explícita de adaptadores de plataforma e uso consistente de manipulação de caminhos multiplataforma. |
| **RNF-11** | Zero Compilação Nativa Obrigatória no MVP | A stack inicial não deve exigir compilador C++ (MSVC/Build Tools) instalado na máquina do usuário para instalar e rodar o SYNAPSE no Windows. | Validação prática: ambiente local não possui `cl.exe`; uso de `node:sqlite` nativo atende esse requisito. |

### 3.5 Manutenibilidade, Testabilidade e Observabilidade

| ID | Categoria | Requisito | Critério de Verificação |
| :--- | :--- | :--- | :--- |
| **RNF-12** | Tipagem Estrita e Validação em Fronteiras | Todo o código TypeScript deve usar modo `strict` e todas as entradas externas (CLI, respostas de IA, configuração, argumentos de ferramentas) devem ser validadas em runtime com Zod. | Compilação `tsc --noEmit` sem erros e schemas Zod cobrindo todas as fronteiras. |
| **RNF-13** | Testabilidade Isolada | Todos os módulos devem receber dependências por injeção (interfaces), permitindo testes unitários rápidos com Vitest sem chamadas reais de API de IA ou mutação acidental do sistema. | Cobertura de testes unitários por módulo + testes de integração em diretórios temporários isolados. |
| **RNF-14** | Logs Estruturados | Eventos operacionais do sistema devem ser emitidos em formato estruturado (JSON) via Pino com níveis configuráveis e correlação por `sessionId` e `taskId`. | Inspeção dos logs gerados em testes de fluxo ponta a ponta. |
| **RNF-15** | Versionamento Disciplinado | O desenvolvimento deve seguir Conventional Commits, entregas incrementais verificadas e controle explícito sobre publicações remotas. | Histórico Git coerente e auditável desde a Fase 0. |
