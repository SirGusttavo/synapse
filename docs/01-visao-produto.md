# 01 — Documento de Visão do Produto

## 1. Declaração de Visão

O **SYNAPSE** é uma infraestrutura universal de execução, comunicação, automação e orquestração que conecta agentes de inteligência artificial ao ambiente operacional de computadores por meio de ferramentas controladas, auditáveis e extensíveis.

Seu princípio central estabelece uma fronteira clara de responsabilidades:

> **A IA pensa, planeja e decide.**
> **O SYNAPSE controla, executa, registra e devolve resultados.**

---

## 2. Problema que o SYNAPSE Resolve

Modelos de linguagem modernos possuem alta capacidade de análise, planejamento e geração de código, mas são sistemas isolados: não executam comandos, não inspecionam arquivos locais nem versionam alterações por conta própria.

Quando equipes ou desenvolvedores conectam agentes diretamente ao sistema operacional sem uma camada intermediária estruturada, surgem problemas recorrentes:

1. **Acoplamento a um único provedor de IA:** integrações construídas sob medida para a API de um único fornecedor dificultam troca de modelos, comparação de custos e uso híbrido.
2. **Risco operacional e de segurança:** delegar execução direta em shell sem validação de caminhos, argumentos, permissões ou aprovação humana expõe o ambiente a perda de dados, vazamento de credenciais e alterações fora do escopo.
3. **Falta de rastreabilidade:** operações disparadas por agentes frequentemente não deixam trilha auditável estruturada (quem pediu, o que rodou, onde rodou, se houve aprovação e qual foi o resultado).
4. **Baixa portabilidade e manutenibilidade:** misturar lógica de IA, regras de permissão e particularidades de um shell específico (como PowerShell ou Bash) produz código frágil e difícil de testar.

O SYNAPSE resolve essas lacunas atuando como um **plano de controle e execução local**, independente de provedor e de interface gráfica.

---

## 3. Proposta de Valor

| Dimensão | Sem SYNAPSE (Scripts / Wrappers Ad-hoc) | Com SYNAPSE |
| :--- | :--- | :--- |
| **Provedores de IA** | Acoplado a uma API específica | Abstração via `Agent Gateway` extensível |
| **Segurança** | Nenhuma ou apenas blocklist simples de strings | Camada dedicada com validação estrutural, confinamento de workspace e aprovações |
| **Execução** | Comandos soltos sem controle de ciclo de vida | `Execution Engine` com timeout, captura padronizada e gerenciamento de processos |
| **Auditoria** | Logs dispersos ou inexistentes | `Audit Logger` estruturado, persistido e com redaction de segredos |
| **Evolução** | Difícil adicionar shells, ferramentas ou UI | Arquitetura modular, testável e desacoplada da interface |

---

## 4. Objetivos do Produto

### Objetivos Principais
- Conectar diferentes provedores e modelos de IA sob um contrato unificado de conversação e *tool calling*.
- Permitir execução controlada de comandos no ambiente operacional autorizado.
- Gerenciar arquivos e diretórios com restrições estritas de acesso ao workspace.
- Integrar operações de versionamento Git com verificações preventivas antes de ações mutáveis ou destrutivas.
- Orquestrar tarefas de agentes com estados explícitos, controle de concorrência e cancelamento.
- Implementar política configurável de permissões e fluxo de aprovação humana.
- Registrar operações, decisões de segurança e resultados de forma estruturada e auditável.
- Permitir extensão futura por módulos, provedores, shells e plugins.
- Evoluir para infraestrutura multiplataforma, começando com prioridade no Windows + PowerShell sem travar o design ao Windows.

### Público-Alvo Inicial
- Desenvolvedores de software e engenheiros de sistemas que desejam executar fluxos assistidos por agentes com controle real sobre segurança, auditoria e escolha de modelos.
- Equipes de automação/DevOps que precisam integrar capacidades agênticas a ambientes locais sem depender de uma IDE ou fornecedor fechado.

---

## 5. Princípios Arquiteturais Inegociáveis

1. **Modularidade:** cada módulo tem responsabilidade única e fronteiras explícitas.
2. **Extensibilidade:** novos provedores, shells, ferramentas e políticas entram por interfaces definidas, sem reescrever o núcleo.
3. **Segurança por padrão (*Secure by Default*):** privilégio mínimo; operações ambíguas ou fora de política são negadas ou exigem confirmação humana.
4. **Rastreabilidade:** toda solicitação relevante gera registro auditável, preservando sigilo de credenciais.
5. **Separação de responsabilidades:** inteligência (LLM), orquestração (tarefas/sessões), governança (segurança/aprovação) e execução (SO) permanecem desacoplados.
6. **Testabilidade:** cada componente pode ser validado isoladamente por testes automatizados com dublês controlados.
7. **Portabilidade:** especificidades do Windows/PowerShell ficam isoladas em adaptadores.
8. **Manutenibilidade:** evitar abstrações prematuras, complexidade especulativa e dependências desnecessárias.

---

## 6. Escopo do MVP vs. Evoluções Futuras

### Dentro do Escopo do MVP (Fases 1 a 4)
- CLI funcional e consistente desacoplada do núcleo.
- `Execution Engine` com timeouts, captura de `stdout`/`stderr`, códigos de saída e encerramento controlado de processos.
- `Shell Manager` com suporte inicial a PowerShell no Windows.
- `File Manager` confinado ao workspace autorizado.
- `Git Manager` com operações essenciais e verificações de segurança.
- `Agent Gateway` integrado inicialmente a um provedor de IA validado, suportando ciclo completo de *tool calling* e gestão de sessões.
- `Task Manager` gerenciando ciclo de vida, fila/concorrência e cancelamento.
- `Security Layer` com níveis de permissão configuráveis, bloqueios padrão, proteção de credenciais e solicitação de aprovação humana.
- `Audit Logger` persistindo histórico local em SQLite e logs estruturados sem vazar segredos.

### Explicitamente Fora do Escopo do MVP (Fase 5+)
- Interface gráfica (Desktop ou Web UI).
- Integração simultânea com todos os provedores de IA desde o primeiro marco.
- Suporte completo a Bash/Zsh em produção (embora a interface `IShellAdapter` já preveja isso desde o início).
- Sistema completo de plugins de terceiros carregados dinamicamente.
- Orquestração distribuída de múltiplos agentes simultâneos em rede.
- Execução remota em servidores ou containers gerenciados (sandboxes em container/VM serão avaliados na evolução).

---

## 7. Não-Objetivos

O SYNAPSE **não** tem como objetivo:
- Ser um emulador de terminal genérico com chat embutido.
- Substituir o controle humano em decisões destrutivas ou de publicação de código.
- Treinar, hospedar ou inferir pesos de modelos de IA internamente (embora possa se conectar a servidores locais de inferência no futuro).
- Assumir que assinaturas de uso pessoal de plataformas de IA fornecem acesso ilimitado via API.
