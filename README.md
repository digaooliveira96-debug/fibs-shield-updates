# MEC Shield Enterprise — Canal Oficial de Atualização

![Versão](https://img.shields.io/badge/vers%C3%A3o-2.2.30-2563eb) ![Assinatura](https://img.shields.io/badge/manifesto-RSA--3072%20%2B%20SHA--256-16a34a) ![Plataforma](https://img.shields.io/badge/Windows-7%20a%20Server%202025-0ea5e9)

Canal de distribuição do **MEC Shield Enterprise**, sistema de backup contínuo 24/7 para bancos Firebird do Sismotel.

Este repositório contém **apenas os arquivos publicados** que o módulo **MEC LiveUpdate** baixa nos servidores. Aqui não há credencial, configuração de cliente nem dado operacional.

## Versão atual: 2.2.30 (28/09/2026)

- O painel não guarda credencial de rede em tarefa sem destino de rede. Sobras antigas são limpas ao salvar a tarefa.
- **Três camadas ativas de verdade:** o serviço do Windows, o **Watchdog** (a cada 2 minutos) e o **Startup Guard** (no boot) são garantidos a cada início do serviço. Antes, o Watchdog e o Startup Guard nunca chegavam a ser registrados.
- O botão **Parar** do painel pausa o Watchdog. Qualquer início ou reboot o reativa.
- O instalador não pede nem grava senha. E-mail e senha de alertas são configurados no painel, em **Preferências**.
- Credencial de rede **opcional** por tarefa, com o botão **Testar Acesso como SYSTEM**, que faz uma gravação real pela conta do backup automático.
- Proteção de disco: abre espaço apagando os backups mais antigos (sempre preserva os 3 mais recentes) ou recusa a cópia, sem nunca lotar o disco do banco.
- Auditoria com folga de 2,5× o tamanho do banco; partições do sistema reconhecidas só pelo rótulo exato ou por terem menos de 1 GB.
- A atualização é feita na pasta da instalação existente, e o serviço é reconfigurado sem ser removido.

## Conteúdo

| Arquivo | Finalidade |
|---|---|
| `version.json` | Manifesto **assinado**: versão, changelog, hashes SHA-256 e assinatura RSA |
| `MEC_Shield_Setup.exe` | Instalador completo (painel, serviço e motor), instalado em modo silencioso |
| `backup_engine.ps1` | Motor de backup (atualização avulsa, caso o instalador falhe) |
| `MEC_Shield.exe` | Painel de gestão |
| `MEC_Shield_Service.exe` | Serviço Windows 24/7 |

## Como o servidor atualiza

1. O serviço verifica o canal **1 vez por dia, às 04:15**, e também quando o serviço reinicia. O botão do painel faz a verificação na hora.
2. O `version.json` é baixado. Ele só é aceito se a **assinatura RSA-3072** conferir com a chave pública que vem instalada no servidor.
3. O instalador é baixado e o **SHA-256** dele precisa ser igual ao do manifesto assinado. Se não for, nada é executado.
4. O instalador roda em **modo silencioso**, na mesma pasta da instalação existente, preservando `config.json`, senhas e sequência de backups.
5. Se o instalador falhar, apenas o motor é atualizado, com a mesma exigência de hash assinado. Uma cópia da versão anterior fica em `.bak`.
6. A mesma versão nunca é reinstalada em menos de 24 horas.

Mesmo que este repositório seja comprometido, os servidores recusam arquivos que não tenham a assinatura da MEC.

## Não versionar aqui

`config.json`, `configurar_discos.ps1`, logs, `network_tracker.json`, `backup_state.json`, `fibs_state.json`, `last_run.json`, `backup_sequence.json` e qualquer arquivo com credenciais ou dados de cliente. Ver `.gitignore`.

---
MEC Tecnologias Corporativas
