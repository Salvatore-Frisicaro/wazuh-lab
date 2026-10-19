# Wazuh SOC Lab — Account Creation Detection (MITRE T1098)

> Abstract
> A Wazuh 4.14.9 SOC lab that detects local account creation and deletion on a
> Windows 10 endpoint (Windows Security events 4720/4726, Wazuh rules 60109/60111,
> MITRE T1098), documenting the full pipeline from agent enrollment to validated alerts.
>
> It also documents the operational failures hit while building it a full disk that
> put the indexer's indices in read-only mode and left the Wazuh API down with the
> diagnosis and fix for each.
>
> The lab is reproducible through documented commands and VirtualBox snapshots;
> it is a learning environment, not a production deployment.

## Obiettivo

Questo laboratorio (Wazuh 4.14.9 all-in-one, Amazon Linux 2023, 4 vCPU / 6 GB)
dimostra una catena di detection completa su un comportamento usato dagli attaccanti
per la persistenza: la creazione di un account locale (evento Windows 4720, MITRE
T1098). Il valore non è l'installazione del SIEM, ma la verifica end-to-end.

Sulla VM Windows 10 Pro N (nome VM `Win10-Lab-01`, hostname `DESKTOP-8CAJRTO`) è
stato creato un account locale. L'evento 4720 è stato raccolto dall'agent Wazuh
installato sull'endpoint e inoltrato al manager, dove il ruleset lo ha mappato con
la regola 60109 (level 8). L'eliminazione dello stesso account (evento 4726) ha
generato un secondo alert con la regola 60111 (level 8). Il ruleset Wazuh mappa
entrambi gli eventi alla tecnica MITRE T1098 (Account Manipulation, Persistence).

L'ambiente è riproducibile tramite comandi documentati e snapshot VirtualBox
(`01-Base-pulita`, `02-M1-funzionante`); non è un ambiente di produzione.

## Architettura

## Componenti e porte

## Setup del laboratorio

## Evidenze: evento 4720

## Hardening

## Problemi incontrati e risolti

## Limiti e prossimi passi