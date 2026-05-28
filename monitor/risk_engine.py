import logging
import threading
import time

from core.runtime_state import runtime_state
from monitor.event_bus import event_bus

logger = get_logger("risk_engine")


class RiskEngine:
    def __init__(self):
        self.risk_score = 0.0
        self.current_risk_level = "NORMAL"
        self._lock = threading.RLock()

        self.event_weights = {
            # Rule-based events
            "HONEYPOT_DIRECTORY_ACCESS": 0.95,
            "POSSIBLE_RANSOMWARE_ACTIVITY": 0.60,
            "MASS_FILE_MODIFICATION": 0.45,
            "TOKEN_REPLAY_ATTEMPT": 0.60,
            "ABNORMAL_PROCESS_CHAIN": 0.35,
            "SUSPICIOUS_POWERSHELL_CHAIN": 0.50,
            "EXFILTRATION_PATTERN_DETECTED": 0.65,
            "CREDENTIAL_STUFFING": 0.25,
            # Behavioral events
            "BEHAVIORAL_DEVIATION_HIGH": 0.10,
            "FAILED_AUTH_BURST": 0.15,
            "SUSPICIOUS_PROCESS": 0.25,
        }

        event_bus.subscribe(self.process_event)
        threading.Thread(target=self._risk_decay_loop, daemon=True).start()
        logger.info("Risk Engine Initialized")

    def _risk_decay_loop(self):
        """Periodically decay the risk score to allow the system to return to normal."""
        while True:
            time.sleep(1)
            with self._lock:
                if self.risk_score > 0:
                    self.risk_score *= 0.97  # Decay factor
                    if self.risk_score < 0.01:
                        self.risk_score = 0
                    self._check_level_change()

    def process_event(self, event: dict):
        """Process an event and update the risk score."""
        event_type = event.get("event_type", "")
        weight = self.event_weights.get(event_type, 0)
 # Changed 'type' to 'event_type'
        # Special handling for ML behavioral deviation
        if event_type in {"ML_ANOMALY", "ML_TELEMETRY"}:
            score = event.get("score", 0)
            # Normalize score from [-1, 1] to [0, 1]
            normalized_score = 1 - ((score - (-1.0)) / (1.0 - (-1.0)))
            runtime_state.update(behavioral_deviation=normalized_score)
            if normalized_score > 0.7:
                weight = self.event_weights.get("BEHAVIORAL_DEVIATION_HIGH", 0.10)

        if weight > 0:
            with self._lock:
                self.risk_score += weight
                self.risk_score = min(self.risk_score, 1.0)  # Cap at 1.0
                logger.info(f"Risk score updated to {self.risk_score:.2f} due to event: {event_type}")
                self._check_level_change()

    def _check_level_change(self):
        """Check if the risk level has changed and publish an event if it has."""
        new_level = self._calculate_risk_level()
        if new_level != self.current_risk_level:
            self.current_risk_level = new_level
            logger.warning(f"Risk level changed to: {new_level}")
            event_bus.publish({
                "event_type": "RISK_LEVEL_CHANGED",
                "risk_level": new_level,
                "risk_score": self.risk_score,
                "timestamp": time.time(),
            })
            runtime_state.update(risk_level=new_level, risk_score=self.risk_score)

    def _calculate_risk_level(self) -> str:
        """Calculate the current risk level based on the score."""
        if self.risk_score >= 0.7:
            return "CRITICAL"
        if self.risk_score >= 0.5:
            return "HIGH"
        if self.risk_score >= 0.3:
            return "SUSPICIOUS"
        return "NORMAL"


risk_engine = RiskEngine()