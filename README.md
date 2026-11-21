# SYNAPSE

**Universal AI Agent Execution & Orchestration Platform**

> *A IA pensa, planeja e decide. O SYNAPSE controla, executa, registra e devolve resultados.*

---

## Status do Projeto

- **Fase atual:** Fase 0 — Discovery e Arquitetura
- **Estado:** Documentação arquitetural concluída para revisão e aprovação antes da Fase 1 (Core).
- **Repositório oficial:** `https://github.com/SirGusttavo/synapse.git`

## O que é o SYNAPSE

O **SYNAPSE** é uma camada intermediária modular, auditável e segura que conecta agentes de inteligência artificial ao ambiente operacional de computadores. Em vez de acoplar um modelo específico a scripts ad-hoc ou a um terminal simples, o SYNAPSE fornece uma infraestrutura padronizada para:

- Conectar múltiplos provedores de IA de forma desacoplada;
- Interpretar chamadas de ferramentas (*tool calling*) com validação estrita de contratos;
- Aplicar políticas de permissão e aprovações humanas antes de efeitos colaterais sensíveis;
- Executar operações reais no sistema operacional (shell, arquivos e Git) com controle de processos e limites;
- Registrar uma trilha de auditoria completa sem expor credenciais.

## Índice da Documentação (Fase 0)

| Documento | Conteúdo |
| :--- | :--- |
| [01 — Visão do Produto](docs/01-visao-produto.md) | Problema, proposta de valor, princípios, objetivos, escopo do MVP e não-objetivos |
| [02 — Requisitos Funcionais e Não Funcionais](docs/02-requisitos.md) | Catálogo estruturado de requisitos funcionais (RF) e não funcionais (RNF) |
| [03 — Arquitetura Proposta](docs/03-arquitetura.md) | Arquitetura modular, diagrama de componentes, fluxo agente-executor e estrutura de diretórios |
| [04 — Stack Tecnológica](docs/04-stack-tecnologica.md) | Baseline do ambiente local, avaliação de dependências, licenças e taxonomia de integrações de IA |
| [05 — Segurança e Matriz de Permissões](docs/05-seguranca-permissoes.md) | Defesa em profundidade, matriz de permissões, proteção de credenciais, auditoria e isolamento |
| [06 — Riscos e Limitações](docs/06-riscos-limitacoes.md) | Riscos técnicos, operacionais, de segurança, de custos e limitações conhecidas |
| [07 — Roadmap Técnico e Critérios do MVP](docs/07-roadmap-mvp.md) | Plano em fases (0 a 5), estratégia de segurança incremental e critérios objetivos de aceitação |
| [08 — Decisões Pendentes](docs/08-decisoes-pendentes.md) | Decisões arquiteturais em aberto que exigem definição antes da Fase 1 |

---

**SYNAPSE — From Intelligence to Action.**
