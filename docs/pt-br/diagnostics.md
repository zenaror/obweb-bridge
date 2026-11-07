# Diagnóstico (Linux)

[Índice dos guias](../../README.PTBR.md) · [English](../en/diagnostics.md) · [Português (Brasil)](../pt-br/diagnostics.md) · [Español](../es/diagnostics.md)

Antes de começar, conclua os [pré-requisitos](prerequisites.md). Execute os comandos na pasta do aplicativo.

Com a ponte em execução, use outro terminal:

```sh
sudo .venv/bin/python app/diagnose.py --lan-interface INTERFACE --pcsx2-ip IP_DO_PS2 --seconds 45
```

No modo Ethernet local, use o IP do PS2 atribuído pelo DHCP remoto, visível nas configurações de rede do jogo. O diagnóstico monitora apenas `obw-pcsx2` para esse IP e informa contadores da interface e metadados de protocolo sem registrar payloads, endereços MAC, nomes DNS, credenciais ou endereços IP. Para exibir no terminal somente os nomes consultados por DNS nessa captura do PS2, acrescente explicitamente `--show-dns-names`; eles não são salvos. Para um cliente separado na LAN, omita `--pcsx2-ip` e use `--client-ip IP_DO_CLIENTE` para limitar a captura a esse dispositivo.

Continue em [Android / ARMSX2](android.md) ou [PS2 real](ps2.md). Para outro computador pela LAN, defina o gateway e DNS da rede dele como o IP do computador da ponte e selecione Sockets no emulador.

---

Guias relacionados: [Pré-requisitos: patch do jogo, Python e conta](prerequisites.md) · [PCSX2 no mesmo computador Windows](windows.md) · [PCSX2 no mesmo computador Linux](linux.md) · [ARMSX2 no Android](android.md) · [PlayStation 2 real](ps2.md) · [Container no Linux](container.md)

## Diagnóstico de reconexões WSS

No modo Ethernet local, o log conta mensagens de texto WSS separadamente dos quadros Ethernet. `peer_gone` e `peer_trk` indicam que um texto JSON válido continha o marcador conhecido `kk-peer-gone` ou `kk-peer-trk`; `other_json` e `non_json` cobrem os demais textos. Esses avisos são ignorados pelo relay. Só a primeira ocorrência de cada categoria é registrada por sessão; os contadores aparecem a cada 30 segundos e ao encerrar o relay. Os contadores recomeçam a cada sessão do relay.

As linhas de reconexão incluem um motivo local e a duração da sessão. Quando disponíveis, também incluem códigos numéricos de fechamento WebSocket, status HTTP do handshake ou números de erro do sistema. O número da tentativa e a indicação de DHCP do emulador ajudam a distinguir falhas antes do tráfego do jogo de quedas durante a partida. Motivos de fechamento remotos, conteúdo JSON, conteúdo dos pacotes e credenciais não são registrados. Após reproduzir o problema, use **Copy diagnostic report** e informe o horário aproximado da falha.
