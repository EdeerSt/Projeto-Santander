1. Visão Geral

Este desafio consiste no desenvolvimento, análise e documentação de provas de conceito (PoCs) de malware simulados em Python, contemplando um ransomware simplificado e um keylogger funcional, executados exclusivamente em ambiente controlado. O objetivo é compreender, de forma prática, técnicas fundamentais utilizadas por agentes maliciosos, bem como reforçar conhecimentos de defesa, resposta a incidentes e análise comportamental.

2. Escopo e Diretrizes de Segurança

A atividade deve ser conduzida estritamente em ambiente isolado, como:

Máquinas virtuais (VMware/VirtualBox)

Sandboxes locais

Hardware descartável destinado a testes

É terminantemente proibido executar qualquer parte do conteúdo em sistemas de produção, dispositivos pessoais ou ambientes de terceiros. O desafio possui finalidade exclusivamente educacional e de pesquisa.

3. Descrição do Desafio

O participante deverá implementar, documentar e analisar dois módulos distintos:

3.1 – Ransomware Simulado (PoC)

Implementar um ransomware simplificado com as seguintes capacidades:

Funcionalidades obrigatórias

Identificação de diretório-alvo contendo arquivos de teste (TXT, JPG, PDF, etc.)

Implementação de algoritmo de criptografia simétrica (recomendado: Fernet/AES)

Geração de chave única para descriptografia

Rotina de criptografia recursiva em múltiplos arquivos

Rotina capaz de realizar o processo reverso (descriptografia)

Geração automática de uma nota de resgate (“ransom note”), contendo:

ID da vítima (simulado)

Instruções de recuperação

Indicação da chave necessária

Documentação técnica

Arquitetura do ransomware

Fluxo de execução (diagrama opcional)

Implementação da criptografia (alto nível, sem expor chaves reais)

Análise sobre como ransomwares reais operam (movimentação lateral, persistência, entrega de chave, C2, etc.)

Vetores comuns de infecção

Como detectar e mitigar ransomware (EDR, logs, heurística, backup, segmentation)

3.2 – Keylogger Simulado (PoC)

Implementar um keylogger funcional com foco em coleta e exfiltração de dados para fins acadêmicos.

Funcionalidades obrigatórias

Captura de eventos de teclado em baixa ou alta frequência

Registro de teclas em arquivo local (TXT ou LOG)

Execução sem interface (background)

Implementação de mecanismos básicos de furtividade, como:

Ocultação da janela de execução

Nome de processo não suspeito

Local de armazenamento camuflado

Funcionalidades opcionais (recomendadas)

Rotina de exfiltração automática via SMTP (e-mail)

Envio periódico dos logs

Compressão e/ou criptografia do log antes do envio

Documentação técnica

Funcionamento interno de keyloggers

Técnicas de hooking (keyboard hooks), APIs comumente utilizadas

Mecanismos de persistência (opcional, somente documentar)

Métodos de detecção (heurística, assinaturas, monitoramento de processos, EDR)

Estratégias de defesa para ambiente corporativo e doméstico

3.3 – Reflexão Técnica de Defesa

Produzir um relatório contendo:

Práticas recomendadas de hardening

Políticas de segurança aplicáveis

Ferramentas e técnicas de detecção (antimalware, EDR, Sysmon, IDS/IPS)

Comparação entre comportamento do malware simulado e amostras reais

Considerações sobre engenharia reversa e análise comportamental

Avaliação de impacto (CIA Triad – Confidencialidade, Integridade, Disponibilidade)

4. Requisitos de Entrega

Recomenda-se utilizar um repositório GitHub com a seguinte estrutura:

malware-simulation-python/
│
├── ransomware/
│   ├── encrypt.py
│   ├── decrypt.py
│   ├── ransom_note.txt
│   ├── test_files/
│   └── README.md
│
├── keylogger/
│   ├── keylogger.py
│   ├── stealth_keylogger.py
│   ├── log_output/
│   └── README.md
│
├── documentation/
│   ├── ransomware_analysis.md
│   ├── keylogger_analysis.md
│   ├── defensive_strategies.md
│   └── architecture_overview.md
│
└── README.md
