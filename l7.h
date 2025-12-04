#ifndef L7_H
#define L7_H

/* Décodeurs applicatifs (couche 7).
   Ils sont appelés depuis L4 (TCP/UDP) quand un port connu est détecté.
   Objectif : affichage simple/pédagogique, pas de décodage exhaustif. */
void try_dns  (const unsigned char *p, int len); /* UDP/53 */
void try_dhcp (const unsigned char *p, int len); /* UDP/67-68 */
void try_http (const unsigned char *p, int len); /* TCP/80 */
void try_ftp  (const unsigned char *p, int len); /* TCP/21 (contrôle) */
void try_smtp (const unsigned char *p, int len); /* TCP/25 (contrôle) */

#endif /* L7_H */
