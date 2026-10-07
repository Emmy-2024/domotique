"""
TP Sécurité IoT (version longue, ~10-13h) — Squelette de démarrage
====================================================================
Complétez les fonctions marquées TODO, dans l'ordre du document
TP_securite_iot.md. Chaque section du fichier correspond à une partie
de l'énoncé.
"""

import json
import re
import math
import hashlib
import hmac as hmac_lib
from collections import defaultdict, Counter

import tracemalloc

import os

# ============================================================
# PARTIE 2 — PARSERS PROTOCOLAIRES
# ============================================================

def parse_zigbee_line(line: str) -> dict | None:
    """Voir énoncé Partie 2, Exercice 2.1."""

    #regex
    pattern = r"topic 'zigbee2mqtt/([^']+)'\s*,\s*payload '({.*})'"
    
    # cherche le pattern n'importe où dans la chaine
    match = re.search(pattern, line)

    if not match:
        return None

    device = match.group(1)
    payload = json.loads(match.group(2))

    return {
        "device": device,
        "payload": payload
    }
   


def parse_zwave_line(line: str) -> dict | None:
    """Voir énoncé Partie 2, Exercice 2.2."""
    pattern = r"Z-WAVE: \[Node (\d+)\] Value updated: 49-0-Power ([\d.,]+) => ([\d.,]+)"



    match = re.search(pattern, line)
    if not match:
        return None

    node = match.group(1)
    last_power = float(match.group(2))
    power = float(match.group(3))
    return {
        "node" : node,
        "power" : power,
        "last_power" : last_power
    }
    

def parse_ha_line(line: str) -> dict | None:
    """Voir énoncé Partie 2, Exercice 2.3."""
    data = json.loads(line)

    state = data["state"]
    if not (state == "on" or state == "off" or state == "unavailable"):
        data["state"] = float(state)
    return data


# ============================================================
# PARTIE 3 — NORMALISATION SÉMANTIQUE
# ============================================================

ZIGBEE_KNOWN_FIELDS = {
    "power": "power",
    "current": "current",
    "voltage": "voltage",
    "energy": "energy",
    "battery": "battery",
    "linkquality": "link_quality",
}

# Champs à considérer comme "safety_critical" : voir Exercice 3.4.
# Un événement marqué ainsi doit toujours passer, quel que soit le
# filtre deadband (Property 2 du papier de recherche associé).
SAFETY_CRITICAL_FIELDS = {"alarm", "tamper", "contact"}

"""
{
" device_id " - str ,
" protocol " - " zigbee " | " zwave " | " ha " ,
" metric_name " - str ,
" metric_value " - float | None ,
" safety_critical " - bool ,
" raw " - dict ,
}
"""

def normalize_zigbee(parsed: dict) -> list[dict]:
    """Voir énoncé Partie 3, Exercices 3.1 à 3.4."""
    payload = parsed["payload"]
    list_event = []
    print(type(parsed["payload"]))
    
    for k in parsed["payload"] : 
        
        event = {" device_id " : parsed["device"] ,
            " protocol " : " zigbee ",
            " metric_name " : k if k in ZIGBEE_KNOWN_FIELDS else "unknow_"+k,
            " metric_value " : parsed["payload"][k],
            " safety_critical " : k in SAFETY_CRITICAL_FIELDS,
            " raw " :parsed,
        }
        list_event.append(event)
    print("************************************debut*********************************")
    print(list_event)
    print("************************************fin*********************************")
    return list_event

def normalize_zwave(parsed: dict) -> list[dict]:
    """Voir énoncé Partie 3, Exercice 3.5."""
    return [{
        " device_id " : parsed["node"] ,
        " protocol " : " zwave ",
        " metric_name " : "power",
        " metric_value " : parsed["power"],
        " safety_critical " : False ,
        " raw " :parsed,
    }]
   


def normalize_ha(parsed: dict) -> list[dict]:
    """Voir énoncé Partie 3, Exercice 3.5."""
    list_event = []
    for k in parsed.keys():
        event = {
            " device_id " : parsed["entity_id"] ,
            " protocol " : " ha ",
            " metric_name " : k if k in ZIGBEE_KNOWN_FIELDS else "unknow_"+k,
            " metric_value " : parsed[k],
            " safety_critical " : k in SAFETY_CRITICAL_FIELDS ,
            " raw " :parsed,
        }
        list_event.append(event)
    return list_event

# ============================================================
# PARTIE 4 — PARSER STREAMING (fichiers volumineux)
# ============================================================

def naive_ha_load(path: str):
    """
    Tentative naïve : charger tout le fichier avec json.load().
    Utilisée en Partie 4 uniquement pour CONSTATER l'échec — ne modifiez
    pas cette fonction, elle est censée lever une exception sur un
    fichier HA réel (objets JSON concaténés, pas un tableau unique).
    """
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def streaming_parse_ha(path: str):
    """
    Implémentation de l'Algorithme 1 (parseur par comptage d'accolades).
    Doit produire un générateur qui yield chaque objet JSON top-level
    complet, au fur et à mesure, sans jamais garder en mémoire plus
    que l'objet en cours de construction.

    Voir énoncé Partie 4, Exercice 4.2.
    """
    # TODO : buf="", depth=0, incrémenter sur '{', décrémenter sur '}',
    # yield json.loads(buf) quand depth revient à 0
    buf = ""
    depth = 0
    with open ( path , encoding = " utf -8 " ) as f :
        for line in f :
            if "{" in line:
                depth+=1
            if "}" in line:
                depth-=1
            buf += line
            if depth == 0:
                yield json.loads(buf)
                buf = ""
for obj in streaming_parse_ha( "ha_large_sample.txt" ):
    pass
    #print(obj)
"""""
tracemalloc.start ()
for obj in streaming_parse_ha ( " data / ha_large_sample . txt " ):
    pass
current , peak = tracemalloc . get_traced_memory ()
tracemalloc . stop ()
file_size = os . path . getsize ( " data / ha_large_sample . txt " )
"""""
# ============================================================
# PARTIE 5 — FILTRE DEADBAND
# ============================================================

def deadband_filter(events: list[dict], delta: float) -> list[dict]:
    events_transmit = []
    first_value=True
    for i in range(len(events)):
        first_value=True
        if events[i][" safety_critical "]:
            events_transmit.append(events[i])
        elif events[i][" metric_name "] == None:
            events_transmit.append(events[i])
        else:
            for j in range(i - 1, -1, -1):

                if events[i][" metric_name "] == events[j][" metric_name "] and events[i][" device_id "] == events[j][" device_id "] :
                    value_i = events[i][" metric_value "]
                    value_j = events[j][" metric_value "]
                    first_value =False
                    
                    if abs(value_i - value_j) >= delta:
                        events_transmit.append(events[i])
                   
                    break
            if first_value:
                    events_transmit.append(events[i])

    return events_transmit



events = []
with open ( 'zwave_large_sample.log' ) as f :
    for l in f :
        print("ok")
        p = parse_zwave_line (l)
        print(p)
        if p: 
            print("events")
            print(events)
            events += normalize_zwave(p)

deltas = [0.5, 1.0, 2.0, 5.0]

total = len(events)

print(f"Total : {total} événements")
print()
print("delta | Événements restants | % filtré")
print("---------------------------------------")

for delta in deltas:
    filtered = deadband_filter(events, delta)
    remaining = len(filtered)
    percent_filtered = (1 - remaining / total) * 100
    print("delta=",delta,"remaining = ",remaining, "percentage", percent_filtered)
    percent_filtered = (1 - remaining / total) * 100

    


# ============================================================
# PARTIE 6 — RÈGLES DE DÉTECTION DE BASE
# ============================================================

def detect_power_surge(events: list[dict], threshold_w: float = 2000) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.1."""
    alerts = []

    for event in events:
        metric_name = event[" metric_name "]
        metric_value = event[" metric_value "]

        if metric_name == "power" and metric_value is not None:
            if metric_value > threshold_w:
                alerts.append(event)

    return alerts
    
events = []
with open ( 'attack_sample.log' ) as f :
    for l in f :
        print("ok")
        p = parse_zigbee_line (l)
        print(p)
        if p: 
            print("events")
            print(events)
            events += normalize_zigbee(p)
print("nombre d'alerte",len(detect_power_surge(events)))
print(detect_power_surge(events))

def detect_replay(events: list[dict], window: int = 3) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.2."""
    # TODO
    raise NotImplementedError


def detect_rogue_device(events: list[dict], known_devices: set[str]) -> list[dict]:
    """Voir énoncé Partie 6, Exercice 6.3."""
    # TODO
    raise NotImplementedError


def detect_event_storm(events: list[dict], window_events: int = 20,
                        max_per_device: int = 8) -> list[dict]:
    """
    NOUVEAU (Partie 6, Exercice 6.4).
    Alerte si un même device_id produit plus de `max_per_device`
    événements sur une fenêtre glissante des `window_events` derniers
    événements TOUS DEVICES CONFONDUS.

    Indice : parcourez les événements dans l'ordre, maintenez une
    fenêtre glissante (collections.deque de taille max window_events),
    comptez les occurrences par device_id à chaque pas.
    """
    # TODO
    raise NotImplementedError


# ============================================================
# PARTIE 8 — PSEUDONYMISATION HMAC
# ============================================================

def naive_hash_device_id(name: str) -> str:
    """Voir énoncé Partie 8, Exercice 8.1 (à ne PAS utiliser en prod)."""
    # TODO
    raise NotImplementedError


def hmac_pseudonymize(protocol: str, name: str, secret: bytes) -> str:
    """
    Voir énoncé Partie 8, Exercice 8.2.
    Doit reproduire : HMAC-SHA256(secret, "protocol:name")[:20]
    """
    # TODO
    raise NotImplementedError


def dictionary_attack(observed_hashes: set[str], dictionary: list[str], hash_fn) -> dict:
    """
    Voir énoncé Partie 8, Exercice 8.3.
    `hash_fn` est un callable à UN SEUL argument (le nom deviné) — utilisez
    une lambda pour fixer protocole/secret, ex:
        dictionary_attack(observed, dico, lambda name: naive_hash_device_id(name))
    Essaie de retrouver les valeurs d'origine derrière `observed_hashes`
    en précalculant hash_fn(guess) pour chaque `guess` du dictionnaire.
    """
    # TODO
    raise NotImplementedError


# ============================================================
# PARTIE 9 — DÉTECTION PAR ENTROPIE (canaux cachés)
# ============================================================

def shannon_entropy(s: str) -> float:
    """
    Voir énoncé Partie 9, Exercice 9.1.
    H(s) = -sum(p_c * log2(p_c)) pour chaque caractère c de s.
    """
    # TODO
    raise NotImplementedError


def detect_high_entropy_unknown(events: list[dict], threshold: float = 4.5,
                                 min_length: int = 8) -> list[dict]:
    """
    Voir énoncé Partie 9, Exercice 9.2.
    Ne s'applique qu'aux événements "unknown_*" (metric_value is None)
    dont la valeur brute est une chaîne de caractères.
    """
    # TODO
    raise NotImplementedError


# ============================================================
# PARTIE 10 — EXTENSION MITRE (A10-A15)
# ============================================================

MITRE_ARTIFACT_LABELS = {
    "unmapped_linux_cmd": "A10 Privilege Escalation",
    "unmapped_net_cmd": "A11 Reverse Shell",
    "unmapped_persist_cmd": "A12 Persistence Cron/Systemd",
    "unmapped_cred_access": "A13 Credential Access",
    "unmapped_download_cmd": "A14 Command and Control / Dropper",
    "unmapped_lateral_cmd": "A15 Lateral Movement",
}


def detect_mitre_artifact(events: list[dict]) -> list[dict]:
    """Voir énoncé Partie 10, Exercice 10.1."""
    # TODO
    raise NotImplementedError


# ============================================================
# PARTIE 11 — PIPELINE COMPLET ET ÉVALUATION À GRANDE ÉCHELLE
# ============================================================

def run_pipeline(zigbee_path, zwave_path, delta=1.0, known_devices=None,
                  power_threshold=2000):
    """
    Pipeline complet à assembler en Partie 11.
    Doit retourner un dictionnaire de métriques exploitable pour le
    mini-rapport d'évaluation (Exercice 11.2).
    """
    # TODO : réutilisez toutes les fonctions des parties précédentes
    raise NotImplementedError


if __name__ == "__main__":
    KNOWN_DEVICES = {
        "zigbee_prise_5", "zigbee-switch-inwall-4", "zigbee-alarm-1",
        "zigbee-pir-1", "node_002", "node_003",
    }
    # Décommentez au fur et à mesure de votre progression :
    # result = run_pipeline("data/zigbee_large_sample.log",
    #                        "data/zwave_large_sample.log",
    #                        delta=1.0, known_devices=KNOWN_DEVICES)
    # print(result)
    pass
