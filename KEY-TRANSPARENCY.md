# Hardlock — Key Transparency (MVP)

## Objectif
Détecter toute substitution discrète de clés publiques par l’opérateur (ou un MITM) grâce à un journal append-only vérifiable par les clients.

## Composants
- Log append-only: arbre Merkle (feuille = (user_id, device_id, pk, ts, prev_hash)).
- Checkpoints périodiques: Signed Tree Head (STH) avec epoch.
- Gossip clients: échange des STH entre pairs (in-band/out-of-band).
- Witnesses: services tiers signant les STH observés.

## API (contrôle)
- POST /v1/kt/append  → ajoute ou fait tourner une clé (auth forte).
- GET  /v1/kt/sth     → renvoie dernier STH.
- GET  /v1/kt/proof?leaf=... → preuve Merkle d’inclusion.
- GET  /v1/kt/consistency?old=...&new=... → preuve de consistance.

## Client workflow
1) Résolution d’un contact: récupère pk + preuve d’inclusion + STH courant.
2) Vérifie inclusion + consistance vs STH stocké localement.
3) En cas de rotation: notification utilisateur + exigence vérif (SAS/QR).
4) Gossip: compare STH avec contacts/témoins; alerte si divergence.

## Menaces couvertes
- Substitution silencieuse: détectée a posteriori.
- Split-view: détectable via gossip témoin.

## Non couvert ici
- Transport chiffré, anonymisation des requêtes (PIR), sealed-sender.
