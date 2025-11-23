# README — Analyseur Réseau (PCAP)

## 1) Présentation

Ce projet est un petit analyseur de trames réseau basé sur **libpcap**. Il capture en **live** sur une interface ou lit en **offline** depuis un fichier **.pcap**, puis affiche les informations des couches :

* **L2** : Ethernet (+ 802.1Q VLAN)
* **L3** : IPv4, ARP, IPv6
* **L4** : ICMP/ICMPv6, UDP, TCP
* **L7** : DNS, DHCP/BOOTP, HTTP (ligne 1), FTP (contrôle), SMTP (contrôle)

Trois niveaux de verbosité sont supportés :

* `-v 1` : ultra-court (timestamp + longueur) — une ligne par trame
* `-v 2` : résumé clair par couche + détection L7
* `-v 3` : détails complets des en-têtes (tous champs utiles, options, etc.). Les contenus applicatifs sont affichés pour les L7 reconnus.

À l’arrêt (Ctrl-C), un récapitulatif **Performance summary** est imprimé (paquets, octets, durée, débit, stats pcap).

---

## 2) Prérequis

* **OS** : Linux ou macOS (développé/testé sur Linux)
* **libpcap** :

  * Debian/Ubuntu : `sudo apt install libpcap-dev`
  * macOS (Homebrew) : `brew install libpcap`
* Droits capture : exécuter avec `sudo` (sinon autoriser la capture non-root sur l’interface)
* Une interface **UP** valide (ex. `wlp0s20f3`, `eth0`, `en0`, `lo`…)

---

## 3) Arborescence

```
.
├── main.c            # options CLI, boucle pcap, performance summary
├── util.c            # print_summary_line, print_mac, hexdump
│
├── L2.c              # Ethernet + VLAN (802.1Q)
│
├── L3_arp.c          # ARP
├── L3_ipv4.c         # IPv4 (+ dispatch L4)
├── L3_ipv6.c         # IPv6 (+ dispatch L4)
│
├── L4_icmp.c         # ICMPv4 / ICMPv6
├── L4_udp.c          # UDP (+ hooks DNS/DHCP)
├── L4_tcp.c          # TCP (+ hooks HTTP/FTP/SMTP)
│
├── L7_dns.c          # DNS (en-tête + 1 question + 1 réponse)
├── L7_dhcp.c         # DHCP/BOOTP (options 53/50/51/54)
├── L7_http.c         # HTTP (première ligne)
├── L7_ftp.c          # FTP (contrôle, première ligne)
├── L7_smtp.c         # SMTP (contrôle, première ligne)
│
├── decode.h          # API partagée (prototypes + extern g_verbose)
├── compat.h          # Macros portabilité (BSD/Linux pour TCP/UDP/ICMP)
├── bootp.h           # struct BOOTP + constantes DHCP
│
└── Makefile
```

> **Note** : les sources contiennent uniquement des commentaires en anglais, comme demandé.

---

## 4) Compilation

```bash
make          # construit 'analyseur'
make clean    # nettoyage
```

Le Makefile ajoute `-MMD -MP` pour générer des dépendances automatiques `.d`.

---

## 5) Utilisation

```bash
./analyseur (-i <iface> | -o <fichier.pcap>) [-f "<filtre BPF>"] [-v 1|2|3]
```

Options :

* `-i iface` : capture live (ex. `-i wlp0s20f3`)
* `-o fichier.pcap` : lecture offline
* `-f "BPF"` : filtre BPF (ex. `"tcp port 80 and ip6"`)
* `-v` : 1 (court), 2 (résumé), 3 (détaillé). **Défaut : 2**

> Le récapitulatif performance est affiché uniquement à l’arrêt via **Ctrl+C**.

Exemples :

```bash
# Live, IPv4 HTTP en v2
sudo ./analyseur -i wlp0s20f3 -v 2 -f "tcp port 80 and ip"

# Live, IPv6 HTTP en v3 (tous détails)
sudo ./analyseur -i wlp0s20f3 -v 3 -f "tcp port 80 and ip6"

# Offline (pcap enregistré)
./analyseur -o http.pcap -v 3
```

---

## 6) Ce qui est affiché (par niveau)

### v = 1

Une seule ligne par trame :

```
<timestamp> len=<taille>
```

### v = 2

Résumé par couche :

* **L2** : `Ethernet: dst=.. src=.. type=0x....`
* **L3** :

  * `IPv4: a.b.c.d -> e.f.g.h proto=.. ttl=.. len=.. id=..`
  * `IPv6: ... -> ... nh=.. hlim=.. plen=..`
  * `ARP: who-has ... tell ...`
* **L4** :

  * `TCP: sport -> dport` + flags
  * `UDP: sport -> dport len=...`
  * `ICMP(v4/v6): type=.. code=..`
* **L7** (si reconnu) :

  * `HTTP: GET / ...` ou `HTTP/1.1 200 OK`
  * `DNS: id=... qd=... an=...` + Q/A simples
  * `DHCP: type=... server=... lease=...` (options clés)
  * `FTP/SMTP: <première ligne contrôle>`

### v = 3

Détails complets des headers :

* **Ethernet/VLAN** : MACs, EtherType, PCP/DEI/VID (802.1Q)
* **IPv4** : version, IHL, DSCP/ECN, total length, ID, flags/offset, TTL, proto, checksum, options bytes
* **IPv6** : traffic class, flow label, payload length, next-header, hop limit
* **TCP** : ports, seq/ack, data offset, flags, window, checksum, urgptr, options bytes
* **UDP** : ports, length, checksum
* **ICMP/ICMPv6** : type, code, echo id/seq si applicable

> Les contenus applicatifs détaillés sont affichés uniquement pour les protocoles L7 reconnus (DNS/DHCP/HTTP/FTP/SMTP).

Fin d’exécution :

```
=== Performance summary ===
packets=<N> bytes=<B>
duration=<s>
rate: <pps> pkt/s, <mbps> Mbit/s
pcap: ps_recv=<r> ps_drop=<d> ps_ifdrop=<id>
===========================
```

---

## 7) Plan de tests rapides

> Remplacer `wlp0s20f3` si besoin. Les tests sur `lo` fonctionnent même sans accès Internet.

### 1) Smoke test v=1

```bash
sudo ./analyseur -i wlp0s20f3 -v 1
# Ctrl+C après quelques secondes (voir le résumé perf)
```

### 2) TCP simple sur loopback

Terminal 1 (capture) :

```bash
sudo ./analyseur -i lo -v 3 -f "tcp port 12345"
```

Terminal 2 (serveur) :

```bash
nc -l 12345
```

Terminal 3 (client) :

```bash
echo "hello tcp" | nc 127.0.0.1 12345
```

### 3) UDP simple sur loopback

Terminal 1 (capture) :

```bash
sudo ./analyseur -i lo -v 3 -f "udp port 12346"
```

Terminal 2 (serveur) :

```bash
nc -u -l 12346
```

Terminal 3 (client) :

```bash
echo "hello udp" | nc -u 127.0.0.1 12346
```

### 4) HTTP IPv4 et IPv6

```bash
curl -4 -s http://example.com > /dev/null &
sudo ./analyseur -i wlp0s20f3 -v 2 -f "tcp port 80 and ip"

curl -6 -s http://example.com > /dev/null &
sudo ./analyseur -i wlp0s20f3 -v 3 -f "tcp port 80 and ip6"
```

### 5) DNS (UDP/53)

```bash
dig @1.1.1.1 openai.com > /dev/null &
sudo ./analyseur -i wlp0s20f3 -v 2 -f "udp port 53"
```

### 6) ICMP v4 / v6

```bash
ping -c 3 1.1.1.1 > /dev/null &
sudo ./analyseur -i wlp0s20f3 -v 2 -f "icmp"

ping6 -c 3 2606:4700:4700::1111 > /dev/null &
sudo ./analyseur -i wlp0s20f3 -v 2 -f "icmp6"
```

### 7) ARP

```bash
ping -c 1 192.168.1.1 > /dev/null &
sudo ./analyseur -i wlp0s20f3 -v 2 -f "arp"
```

### 8) DHCP (recommandé en offline)

```bash
sudo tcpdump -i wlp0s20f3 -w dhcp.pcap "udp port 67 or udp port 68" -c 50
./analyseur -o dhcp.pcap -v 3
```

---

## 8) Conseils & Dépannage

* **Rien n’apparaît** : vérifier l’interface (`ip -br link`), les droits (sudo), ou retirer/adapter le filtre `-f`.
* **EtherType 0x86dd non reconnu** : s’assurer de ne pas filtrer uniquement `ip` (utiliser `ip6` pour IPv6).
* **Wi‑Fi** : certains pilotes filtrent du trafic (ARP/multicast). Tester sur `lo` ou en filaire si possible.

Limitations volontaires :

* Capture uniquement **DLT_EN10MB** (Ethernet).
* DNS : affichage de **1 question + 1 réponse** pour la lisibilité.
* IPv6 : pas d’analyse des **extension headers** complexes.
* L7 : affichage minimal (ligne 1 HTTP/FTP/SMTP), pas de réassemblage de flux TCP.

---

## 9) Performance

Le programme mesure : nombre de paquets/octets, durée, **pps** et **Mbit/s**, plus `pcap_stats`.

Pour mesurer un trafic plus important : enlever `-f` ou générer du trafic (`ping`, `iperf`, etc.), puis interrompre (Ctrl‑C) pour voir le résumé.

---

## 10) Licence

Projet académique — usage pédagogique.
