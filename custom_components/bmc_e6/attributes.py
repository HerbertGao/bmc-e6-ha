"""Which summary-record fields the integration exposes, and how.

Home Assistant free import: this module only knows protocol field names and unit
conversions, so the coverage test can compare it against the parser output.
"""
from __future__ import annotations

# ---- per-night detail ------------------------------------------------------
# The summary record carries far more than one number per metric. Rather than
# exploding it into dozens of entities, the rest is exposed as attributes on the
# sensor it belongs to. Attribute keys are the protocol field names; the only
# transformation is the unit conversion (verified against captured records).
# Times that are NOT verified to be seconds stay raw: see NOT_ATTRIBUTES.


def _idx(v):        # events/h, stored x10
    return round(v / 10, 1)


def _cmh2o(v):      # cmH2O, stored x100
    return round(v / 100, 2)


def _leak(v):       # L/min, stored x10
    return round(v / 10, 1)


def _mv(v):         # L/min, stored x1000
    return round(v / 1000, 2)


def _ie(v):         # I:E reported as inspiration/expiration (0.448 == 1:2.2)
    return round(v / 1000, 3)


def _insp_s(v):     # inspiratory time is stored in 0.1 s units
    return round(v / 10, 2)


def _stage_min(v):  # sleep-stage times are stored in 2 s units
    return round(v * 2 / 60)


_ATTRS = {
    "ahi": (
        ("ai", "ai", _idx), ("hi", "hi", _idx), ("oai", "oai", _idx), ("cai", "cai", _idx),
        ("uai", "uai", _idx), ("ohi", "ohi", _idx), ("chi", "chi", _idx), ("uhi", "uhi", _idx),
        ("hiWithCh", "hiWithCh", _idx), ("ahiWithCh", "ahiWithCh", _idx),
        ("odi", "odi", _idx), ("sni", "sni", _idx), ("reraIndex", "reraIndex", _idx),
    ),
    "epap_avg": (
        ("initP", "initP", _cmh2o), ("epapMax", "epapMax", _cmh2o),
        ("epap95", "epap95", _cmh2o), ("epap50", "epap50", _cmh2o),
    ),
    "ipap_avg": (
        ("ipapMax", "ipapMax", _cmh2o), ("ipap95", "ipap95", _cmh2o), ("ipap50", "ipap50", _cmh2o),
    ),
    "vt_avg": (("vtMax", "vtMax", int), ("vt95", "vt95", int), ("vt50", "vt50", int)),
    "mv_avg": (("mvMax", "mvMax", _mv), ("mv95", "mv95", _mv), ("mv50", "mv50", _mv)),
    "leak_avg": (
        ("leakMax", "leakMax", _leak), ("leak95", "leak95", _leak), ("leak50", "leak50", _leak),
        ("mouthLeakTime", "mouthLeakTime", int),
    ),
    "rr_avg": (("rrMax", "rrMax", int), ("rr95", "rr95", int), ("rr50", "rr50", int)),
    "spo2_avg": (
        ("spo295", "spo295", int), ("spo250", "spo250", int),
        ("spo2Time95to100", "spo2Time95to100", int), ("spo2Time90to94", "spo2Time90to94", int),
        ("spo2Time85to89", "spo2Time85to89", int), ("spo2Time80to84", "spo2Time80to84", int),
        ("spo2Time75to79", "spo2Time75to79", int), ("spo2Time70to74", "spo2Time70to74", int),
        ("spo2Time0to69", "spo2Time0to69", int),
        ("tst90", "tst90", int), ("odi", "odi", _idx),
    ),
    "pr_avg": (
        ("prMax", "prMax", int), ("prMin", "prMin", int),
        ("pr95", "pr95", int), ("pr50", "pr50", int),
    ),
    "treat_time_h": (
        ("runTime", "runTime", int), ("leakTime", "leakTime", int),
        ("leakTime40L", "leakTime40L", int), ("treatCnt", "treatCnt", int),
        ("sleepStageWakeTime", "sleepStageWakeTime", _stage_min),
        ("sleepStageLightTime", "sleepStageLightTime", _stage_min),
        ("sleepStageDeepTime", "sleepStageDeepTime", _stage_min),
        ("sleepStageWakeCnt", "sleepStageWakeCnt", int),
        ("inspTimeMax", "inspTimeMax", _insp_s), ("inspTimeAvg", "inspTimeAvg", _insp_s),
        ("inspTime95", "inspTime95", _insp_s), ("inspTime50", "inspTime50", _insp_s),
        ("ieAvg", "ieAvg", _ie), ("ieMax", "ieMax", _ie), ("ie95", "ie95", _ie), ("ie50", "ie50", _ie),
        ("hypoBurden", "hypoBurden", int),
        ("mildFlowLimitTime", "mildFlowLimitTime", int),
        ("moderateLimitTime", "moderateLimitTime", int),
        ("severeLimitTime", "severeLimitTime", int), ("snoreTime", "snoreTime", int),
        ("periodicTime", "periodicTime", int),
    ),
}

# Parsed fields that are NOT exposed as attributes, and why. Together with the
# _ATTRS fields this must cover the parser exactly; the coverage test fails if
# the parser gains a field that is in neither, so nothing silently disappears
# again (SpO2 did).
NOT_ATTRIBUTES = frozenset({
    # already the state of an entity
    "ahi", "treatTime", "leakAvg", "epapAvg", "ipapAvg", "vtAvg", "mvAvg", "rrAvg",
    "spo2Avg", "spo2Min", "spo2Max", "prAvg", "spo2Time",
    # provenance / frame metadata
    "recordDate", "recordDate_raw", "recordNo", "headFlag", "size",
    "mainVer", "subVer", "headRev", "buildTime",
    # vendor padding and the trailing checksum
    "reserve", "reserveP", "reserveIndex", "reserve2", "checksum", "_parsed_bytes",
    # no published meaning to report
    "firstMode", "lastMode",   # mode codes without a documented enum
    "sInspRatio", "sExpRatio",  # scale unverified; reporting a wrong ratio is worse
})




def extra_attrs(key: str, rec: dict) -> dict:
    """Convert this sensor's remaining record fields into attributes."""
    out = {}
    for attr, field, transform in _ATTRS.get(key, ()):
        value = rec.get(field)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            out[attr] = transform(value)
    return out
