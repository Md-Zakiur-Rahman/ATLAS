"""
ATLAS ML Detector

Adaptive anomaly detection using
Isolation Forest.

FIXES APPLIED (Day 6):
  1. __init__ moved to top of class.
  2. contamination lowered 0.05 → 0.01.
  3. MIN_SAMPLES raised 10 → 60.
  4. Thresholds recalibrated.
  5. get_severity_from_score indentation fixed.
  6. analyze_latest_features logs every cycle.

ADDED:
  - WEEKLY_MIN_SAMPLES floor for auto retrain.
  - save_history() / load_history() so vectors
    survive app restarts.
  - schedule_retraining() wires weekly Sunday
    retrain + bi-monthly reset + hourly save.
  - _silent_retrain() for weekly retrain.
  - _bimonthly_reset() for full reset every
    2 months on even month 1st at 03:00.

DAY 8 TODOs marked with: # ── TODO D8 ──
"""

import json
import os
import time
import logging
from datetime import datetime
from typing import List

import joblib
import numpy as np
import schedule
from sklearn.ensemble import IsolationForest

from monitor.event_bus import event_bus
from monitor.feature_extractor import feature_extractor

# ── TODO D8 ─────────────────────────────
# from notifications.telegram_bot import telegram_bot
# ────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )
)

logger = logging.getLogger("ATLAS-MLDetector")

# ── FIX 3 ────────────────────────────────
# Minimum samples for --train mode.
# 60 samples ≈ 10 minutes of collection.
MIN_SAMPLES = 60

# Minimum samples for weekly auto retrain.
# 500 ≈ roughly 1.5 hours of data — enough
# to capture a realistic daily pattern.
# The deque maxlen=1000 caps the ceiling.
WEEKLY_MIN_SAMPLES = 500

# File paths
MODEL_PATH   = "assets/model.pkl"
HISTORY_PATH = "assets/feature_history.json"


class MLDetector:

    # ── FIX 1 ────────────────────────────
    # __init__ moved to top of class.
    def __init__(self):

        # ── FIX 2 ────────────────────────
        # contamination=0.01 — expects only
        # 1% of training data to be outliers.
        # Previous 0.05 caused idle env to
        # score in HIGH range constantly.
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.01,
            random_state=42,
        )

        self.model_path   = MODEL_PATH
        self.history_path = HISTORY_PATH
        self.is_trained   = False

    # ═════════════════════════════════════
    # TRAINING
    # ═════════════════════════════════════

    def train(self) -> None:
        """
        Train model on collected baseline
        feature vectors.
        Called by --train flag and by
        scheduled retraining.
        """

        training_data = list(
            feature_extractor.feature_history
        )

        # ── FIX 3 ────────────────────────
        # Raised from 10 → MIN_SAMPLES=60.
        if len(training_data) < MIN_SAMPLES:
            logger.warning(
                "Not enough training data: "
                "%s/%s samples — keep "
                "collecting.",
                len(training_data),
                MIN_SAMPLES,
            )
            return

        X = np.array(training_data)
        self.model.fit(X)
        self.is_trained = True

        logger.info(
            "ML Model Trained On %s Samples",
            len(training_data)
        )

        self.save_model()

        # Always save history after a
        # successful train so vectors
        # survive the next restart.
        self.save_history()

    # ═════════════════════════════════════
    # SCHEDULED RETRAINING
    # ═════════════════════════════════════

    def schedule_retraining(self) -> None:
        """
        Wire weekly + bi-monthly retraining
        and hourly history saves into the
        schedule library.

        Call once on startup AFTER
        load_model() and load_history().

        Requires the scheduler thread in
        main.py to be running.
        """

        # Every Sunday at 02:00
        schedule.every().sunday.at("02:00").do(
            self._silent_retrain
        )

        # Checked monthly — only runs on
        # even months (Feb/Apr/Jun/Aug/Oct/Dec)
        schedule.every().month.at("03:00").do(
            self._bimonthly_reset
        )

        # Flush history to disk every hour
        # so a crash doesn't lose the day's
        # collected vectors.
        schedule.every().hour.do(
            self.save_history
        )

        logger.info(
            "ML Retraining Schedule: "
            "weekly Sun 02:00 | "
            "bi-monthly reset | "
            "hourly history save"
        )

    def _silent_retrain(self) -> None:
        """
        Weekly silent retrain — no user
        interaction needed. Uses whatever
        is in feature_history at the time.
        """

        available = len(
            feature_extractor.feature_history
        )

        if available < WEEKLY_MIN_SAMPLES:
            logger.warning(
                "Weekly retrain skipped — "
                "only %s/%s samples available.",
                available,
                WEEKLY_MIN_SAMPLES,
            )
            return

        logger.info(
            "Weekly silent retrain starting "
            "on %s samples...",
            available,
        )

        self.train()

        logger.info("Weekly retrain complete")

        # LOW severity — shows in log tab
        # but does not raise an alert.
        event_bus.publish({
            "type":      "ML_RETRAINED",
            "reason":    "Weekly scheduled retrain",
            "samples":   available,
            "severity":  "LOW",
            "timestamp": time.time(),
        })

    def _bimonthly_reset(self) -> None:
        """
        Bi-monthly full reset.
        Runs on the 1st of Feb, Apr, Jun,
        Aug, Oct, Dec at 03:00.

        Clears the model and all collected
        history so the system learns a
        completely fresh baseline —
        captures major life/usage changes
        (new semester, new job, etc).
        """

        # schedule fires every month —
        # only execute on even months.
        if datetime.now().month % 2 != 0:
            return

        logger.info(
            "Bi-monthly reset starting — "
            "clearing model and history."
        )

        self.is_trained = False
        feature_extractor.feature_history.clear()

        # Remove saved history file so
        # stale vectors are not reloaded
        # on next startup.
        try:
            if os.path.exists(self.history_path):
                os.remove(self.history_path)
                logger.info(
                    "History file removed: %s",
                    self.history_path,
                )
        except Exception as error:
            logger.warning(
                "Could not remove history "
                "file: %s",
                error,
            )

        # Dashboard banner — tells user ML
        # protection is briefly in rule-based
        # only mode while collecting fresh
        # baseline.
        event_bus.publish({
            "type":      "ML_RETRAINING",
            "reason":    "Bi-monthly reset — collecting fresh baseline",
            "severity":  "LOW",
            "timestamp": time.time(),
        })

        logger.info(
            "Bi-monthly reset complete — "
            "fresh baseline collection has "
            "started. Weekly retrain will "
            "fire once enough data exists."
        )

    # ═════════════════════════════════════
    # HISTORY PERSISTENCE
    # ═════════════════════════════════════

    def save_history(self) -> None:
        """
        Flush feature_history deque to
        disk as JSON.
        Called hourly by scheduler and
        after every successful train().
        """

        try:
            with open(self.history_path, "w") as f:
                json.dump(
                    list(
                        feature_extractor.feature_history
                    ),
                    f,
                )

            logger.info(
                "Feature History Saved: "
                "%s vectors → %s",
                len(feature_extractor.feature_history),
                self.history_path,
            )

        except Exception as error:
            logger.error(
                "History Save Failed: %s",
                error,
            )

    def load_history(self) -> None:
        """
        Load persisted feature vectors
        back into feature_history on
        startup. Allows retraining and
        scoring to use data from previous
        sessions without re-collecting.
        """

        try:
            with open(self.history_path) as f:
                data = json.load(f)

            feature_extractor.feature_history.extend(
                data
            )

            logger.info(
                "Feature History Loaded: "
                "%s vectors from %s",
                len(data),
                self.history_path,
            )

        except FileNotFoundError:
            logger.info(
                "No history file — "
                "starting fresh collection."
            )

        except Exception as error:
            logger.warning(
                "History Load Failed: %s",
                error,
            )

    # ═════════════════════════════════════
    # SCORING & DETECTION
    # ═════════════════════════════════════

    def score(
        self,
        feature_vector: List[float]
    ) -> float:
        """
        Generate anomaly score.
        Lower = more anomalous.
        Expected idle range after fixes:
        approximately -0.10 to -0.25.
        """

        if not self.is_trained:
            logger.warning("Model not trained")
            return 0.0

        X = np.array([feature_vector])
        score = self.model.score_samples(X)[0]

        logger.info(
            "Anomaly Score: %.4f",
            score
        )

        return score

    def predict(
        self,
        feature_vector: List[float]
    ) -> int:
        """
        Returns:
             1 = Normal
            -1 = Anomaly
        """

        if not self.is_trained:
            return 1

        X = np.array([feature_vector])
        return self.model.predict(X)[0]

    # ── FIX 4 + FIX 5 ───────────────────
    # Indentation fixed. Thresholds
    # recalibrated — idle baseline sits
    # around -0.10 to -0.25 after fixes,
    # so real attacks have room to spike.
    def get_severity_from_score(
        self,
        score: float
    ) -> str:

        if score < -0.70:
            return "CRITICAL"

        if score < -0.60:
            return "HIGH"

        if score < -0.50:
            return "MEDIUM"

        return "LOW"

    def analyze_latest_features(
        self
    ) -> None:
        """
        Run live anomaly detection on
        latest feature vector.
        """

        if not self.is_trained:
            logger.warning(
                "ML detection inactive — "
                "run with --train first."
            )
            return

        if not feature_extractor.feature_history:
            logger.warning(
                "No feature history available"
            )
            return

        feature_vector = (
            feature_extractor.feature_history[-1]
        )

        score      = self.score(feature_vector)
        severity   = self.get_severity_from_score(score)
        prediction = self.predict(feature_vector)

        # ── FIX 6 ────────────────────────
        # Log every cycle so idle baseline
        # drift is visible in real time.
        logger.info(
            "ML Prediction: %s | "
            "Score: %.4f | "
            "Severity: %s",
            "ANOMALY" if prediction == -1 else "NORMAL",
            score,
            severity,
        )

        if prediction == -1:

            event_bus.publish({
                "type":           "ML_ANOMALY",
                "score":          score,
                "severity":       severity,
                "feature_vector": feature_vector,
                "prediction":     prediction,
                "timestamp":      time.time(),
            })

            # ── TODO D8 ──────────────────
            # if severity in ("HIGH", "CRITICAL"):
            #     telegram_bot.send_alert(
            #         f"🚨 ML Anomaly\n"
            #         f"Score: {score:.4f}\n"
            #         f"Severity: {severity}"
            #     )
            # ─────────────────────────────

    def start_monitoring(self) -> None:
        """
        Continuous ML monitoring loop.
        Runs in its own daemon thread.
        """

        logger.info("ML Monitoring Started")

        while True:
            try:
                self.analyze_latest_features()
                time.sleep(10)

            except Exception as error:
                logger.exception(
                    "ML Monitoring Error: %s",
                    error
                )

    # ═════════════════════════════════════
    # MODEL PERSISTENCE
    # ═════════════════════════════════════

    def save_model(self) -> None:

        joblib.dump(self.model, self.model_path)

        logger.info(
            "ML Model Saved: %s",
            self.model_path
        )

    def load_model(self) -> None:

        try:
            self.model = joblib.load(self.model_path)
            self.is_trained = True
            logger.info("ML Model Loaded")

        except FileNotFoundError:
            logger.info(
                "No model file — "
                "run with --train to build baseline."
            )

        except Exception as error:
            logger.warning(
                "Model Load Failed: %s",
                error
            )


ml_detector = MLDetector()