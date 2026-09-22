# MEC Shield Enterprise — Canal Oficial de Atualizacao

Canal de distribuicao do **MEC Shield Enterprise**, sistema de backup continuo 24/7
para bancos Firebird do Sismotel.

Este repositorio contem **apenas os artefatos publicados** que o modulo MEC LiveUpdate
consome. Nenhuma credencial, configuracao de cliente ou dado operacional e versionado aqui.

## Conteudo

| Arquivo                  | Finalidade                                         |
|--------------------------|----------------------------------------------------|
| `version.json`           | Manifesto lido pelo LiveUpdate (versao, changelog) |
| `backup_engine.ps1`      | Motor de backup                                    |
| `MEC_Shield.exe`         | Painel de gestao                                   |
| `MEC_Shield_Service.exe` | Servico Windows 24/7                               |

## Como o cliente atualiza

O motor consulta o `version.json` uma vez por dia. Havendo versao maior que a instalada,
baixa o novo `backup_engine.ps1` para uma pasta temporaria, valida tamanho e sintaxe
PowerShell, guarda uma copia da versao anterior em `.bak` e so entao faz a troca.

## Nao versionar aqui

`config.json`, `configurar_discos.ps1`, logs, `network_tracker.json`, `backup_state.json`,
`fibs_state.json` e qualquer arquivo com credenciais de cliente. Ver `.gitignore`.

---
MEC Tecnologias Corporativas
