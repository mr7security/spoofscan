"""Control catalogue in scope for spoofscan.

ENS codes follow Anexo II of Real Decreto 311/2022 as published by the CCN.
ISO codes follow ISO/IEC 27002:2022, whose numbering mirrors Annex A of
ISO/IEC 27001:2022. The cross-mapping is orientative: which controls apply to
a given system is decided by the organisation in its Statement of
Applicability.
"""
from __future__ import annotations

from typing import Dict, List

from .models import Control, T

_ENS: List[Control] = [
    Control(
        "ENS", "mp.s.1",
        T("Email protection", "Proteccion del correo electronico"),
        T("Protection measures / Services", "Medidas de proteccion / Servicios"),
    ),
    Control(
        "ENS", "mp.com.2",
        T("Protection of confidentiality", "Proteccion de la confidencialidad"),
        T("Protection measures / Communications", "Medidas de proteccion / Comunicaciones"),
    ),
    Control(
        "ENS", "mp.com.3",
        T("Protection of integrity and authenticity",
          "Proteccion de la integridad y de la autenticidad"),
        T("Protection measures / Communications", "Medidas de proteccion / Comunicaciones"),
    ),
    Control(
        "ENS", "op.exp.6",
        T("Protection against malicious code", "Proteccion frente a codigo danino"),
        T("Operational framework / Exploitation", "Marco operacional / Explotacion"),
    ),
    Control(
        "ENS", "op.exp.7",
        T("Incident management", "Gestion de incidentes"),
        T("Operational framework / Exploitation", "Marco operacional / Explotacion"),
    ),
    Control(
        "ENS", "op.mon.3",
        T("Surveillance", "Vigilancia"),
        T("Operational framework / Monitoring", "Marco operacional / Monitorizacion"),
    ),
]

_ISO: List[Control] = [
    Control(
        "ISO", "5.14",
        T("Information transfer", "Transferencia de informacion"),
        T("Organizational controls", "Controles organizativos"),
    ),
    Control(
        "ISO", "5.26",
        T("Response to information security incidents",
          "Respuesta a incidentes de seguridad de la informacion"),
        T("Organizational controls", "Controles organizativos"),
    ),
    Control(
        "ISO", "8.7",
        T("Protection against malware", "Proteccion contra el malware"),
        T("Technological controls", "Controles tecnologicos"),
    ),
    Control(
        "ISO", "8.16",
        T("Monitoring activities", "Actividades de seguimiento"),
        T("Technological controls", "Controles tecnologicos"),
    ),
    Control(
        "ISO", "8.20",
        T("Networks security", "Seguridad de redes"),
        T("Technological controls", "Controles tecnologicos"),
    ),
    Control(
        "ISO", "8.21",
        T("Security of network services", "Seguridad de los servicios de red"),
        T("Technological controls", "Controles tecnologicos"),
    ),
    Control(
        "ISO", "8.24",
        T("Use of cryptography", "Uso de criptografia"),
        T("Technological controls", "Controles tecnologicos"),
    ),
]

CONTROLS: Dict[str, Control] = {f"{c.framework}:{c.code}": c for c in _ENS + _ISO}

#: Every control this tool has something to say about. Which of them are truly
#: assessed on a given domain depends on what could be resolved; see
#: :func:`spoofscan.scoring.control_status`.
IN_SCOPE: List[str] = list(CONTROLS.keys())


def get(ref: str) -> Control:
    return CONTROLS[ref]


def resolve(refs: List[str]) -> List[Control]:
    return [CONTROLS[r] for r in refs if r in CONTROLS]


def pretty(refs: List[str]) -> str:
    return " · ".join(c.ref for c in resolve(refs))
