"""
ATLAS ML Detector

Adaptive anomaly detection using
Isolation Forest.
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

INITIAL_MIN_SAMPLES = 1440
MIN_SAMPLES = 60
PARTIAL_MODEL_FLAG = "assets/partial_model.flag"

MODEL_PATH = "assets/model.pkl"
HISTORY_PATH = "assets/feature_history.json"
TRAINING_STATE_PATH = "assets/training_state.json"

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s | "
        "%(levelname)s | "
        "%(message)s"
    )
)

logger = logging.getLogger("ATLAS-MLDetector")


class MLDetector:

    def __init__(self):

        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.01,
            random_state=42,
        )

        self.model_path = MODEL_PATH
        self.history_path = HISTORY_PATH
        self.training_state_path = TRAINING_STATE_PATH
        self.is_trained = False
        self.is_initial_training_complete = False
        self.critical_threshold = None
        self.high_threshold     = None
        self.medium_threshold   = None

    # =====================================
    # TRAINING
    # =====================================

    def train(self) -> None:
        """
        Train model on collected baseline
        feature vectors.
        Called by --train flag and by
        scheduled retraining.
        """

        sample_count = len(
            feature_extractor.feature_history
        )

        if sample_count < MIN_SAMPLES:
            logger.warning(
                "Only %d samples collected - minimum is 60. "
                "Skipping training. History saved for next run.",
                sample_count
            )
            self.save_history()
            return

        if sample_count < INITIAL_MIN_SAMPLES:
            logger.warning(
                "Partial model - only %d of %d samples collected. "
                "Model will work but is not fully calibrated. "
                "Leave ATLAS running to collect a full 4hr baseline - 1440 samples.",
                sample_count,
                INITIAL_MIN_SAMPLES
            )
            os.makedirs("assets", exist_ok=True)
            open(PARTIAL_MODEL_FLAG, "w").close()
            self.is_initial_training_complete = False
            self._save_training_state()

        else:
            if os.path.exists(PARTIAL_MODEL_FLAG):
                os.remove(PARTIAL_MODEL_FLAG)

            self.is_initial_training_complete = True
            self._save_training_state()

        training_data = list(
            feature_extractor.feature_history
        )

        X = np.array(training_data)
        self.model.fit(X)
        scores = self.model.score_samples(X)

        self.critical_threshold = float(np.percentile(scores, 1))
        self.high_threshold     = float(np.percentile(scores, 5))
        self.medium_threshold   = float(np.percentile(scores, 10))

        logger.info(
            "Dynamic thresholds calibrated for this machine - "
            "CRITICAL: %.4f | HIGH: %.4f | MEDIUM: %.4f",
            self.critical_threshold,
            self.high_threshold,
            self.medium_threshold,
        )

        self.is_trained = True

        logger.info(
            "ML Model Trained On %s Samples",
            len(training_data)
        )

        self._save_training_state()
        self.save_model()

        self.save_history()

    # =====================================
    # SCHEDULED RETRAINING
    # =====================================

    def schedule_retraining(self) -> None:
        """
        Wire weekly + bi-monthly retraining
        and hourly history saves into the
        schedule library.
        """

        schedule.every().sunday.at("02:00").do(
            self._silent_retrain
        )

        schedule.every().day.at("03:00").do(
            self._bimonthly_reset
        )

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
        Weekly silent retrain using the
        long-term feature history.
        """

        available = len(
            feature_extractor.feature_history
        )

        if available < INITIAL_MIN_SAMPLES:
            logger.warning(
                "Weekly retrain skipped - "
                "only %s/%s samples available.",
                available,
                INITIAL_MIN_SAMPLES,
            )
            return

        logger.info(
            "Weekly silent retrain starting "
            "on %s samples...",
            available,
        )

        self.train()

        logger.info("Weekly retrain complete")

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
        """

        now = datetime.now()

        if now.day != 1:
            return

        if now.month % 2 != 0:
            return

        logger.info(
            "Bi-monthly reset starting - "
            "clearing model and history."
        )

        self.is_trained = False
        self.is_initial_training_complete = False
        self.critical_threshold = None
        self.high_threshold = None
        self.medium_threshold = None
        feature_extractor.feature_history.clear()
        self._save_training_state()

        event_bus.publish({
            "type":      "ML_RETRAINING",
            "reason":    "Bi-monthly reset",
            "severity":  "LOW",
            "timestamp": time.time(),
        })

        try:
            if os.path.exists(PARTIAL_MODEL_FLAG):
                os.remove(PARTIAL_MODEL_FLAG)

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

        event_bus.publish({
            "type":      "ML_RETRAINING",
            "reason":    "Bi-monthly reset - collecting fresh baseline",
            "severity":  "LOW",
            "timestamp": time.time(),
        })

        logger.info(
            "Bi-monthly reset complete - "
            "fresh baseline collection has "
            "started. Weekly retrain will "
            "fire once enough data exists."
        )

    # =====================================
    # HISTORY PERSISTENCE
    # =====================================

    def save_history(self) -> None:
        """
        Flush feature_history deque to
        disk as JSON.
        Called hourly by scheduler and
        after every successful train().
        """

        try:
            os.makedirs("assets", exist_ok=True)

            with open(self.history_path, "w") as f:
                json.dump(
                    list(
                        feature_extractor.feature_history
                    ),
                    f,
                )

            logger.info(
                "Feature History Saved: "
                "%s vectors -> %s",
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

        except json.JSONDecodeError:
            logger.warning(
                "feature_history.json is corrupted - starting fresh."
            )

        except FileNotFoundError:
            logger.info("No history file - starting fresh.")

        except Exception as error:
            logger.warning(
                "History Load Failed: %s",
                error,
            )

    # =====================================
    # SCORING & DETECTION
    # =====================================

    def score(
        self,
        feature_vector: List[float]
    ) -> float:
        """
        Generate anomaly score.
        Lower = more anomalous.
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

    def get_severity_from_score(
        self,
        score: float
    ) -> str:

        if None in (self.critical_threshold, self.high_threshold, self.medium_threshold):
            logger.warning(
                "Thresholds not set - skipping ML score. "
                "Run --train to calibrate."
            )
            return "LOW"

        if score < self.critical_threshold:
            return "CRITICAL"

        if score < self.high_threshold:
            return "HIGH"

        if score < self.medium_threshold:
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
                "ML detection inactive - "
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

    def start_monitoring(self) -> None:
        """
        Continuous ML monitoring loop.
        Runs in its own daemon thread.
        """

        logger.info("ML Monitoring Started")

        while True:
            try:
                if not self.is_trained:
                    logger.warning(
                        "ML detection inactive - "
                        "run with --train first."
                    )
                    time.sleep(10)
                    continue

                if not feature_extractor.feature_history:
                    logger.warning(
                        "No feature history available"
                    )
                    time.sleep(10)
                    continue

                feature_vector = (
                    feature_extractor.feature_history[-1]
                )

                score = self.score(feature_vector)

                if None in (self.critical_threshold, self.high_threshold, self.medium_threshold):
                    logger.warning(
                        "Thresholds not set - skipping ML score. "
                        "Run --train to calibrate."
                    )
                    time.sleep(10)
                    continue

                if score < self.critical_threshold:
                    severity = "CRITICAL"
                elif score < self.high_threshold:
                    severity = "HIGH"
                elif score < self.medium_threshold:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                prediction = self.predict(feature_vector)

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

                time.sleep(10)

            except Exception as error:
                logger.exception(
                    "ML Monitoring Error: %s",
                    error
                )

    # =====================================
    # MODEL PERSISTENCE
    # =====================================

    def save_model(self) -> None:

        os.makedirs("assets", exist_ok=True)

        joblib.dump(self.model, self.model_path)

        logger.info(
            "ML Model Saved: %s",
            self.model_path
        )

    def _save_training_state(self) -> None:
        import json
        os.makedirs("assets", exist_ok=True)
        state = {
            "is_initial_training_complete": self.is_initial_training_complete,
            "critical_threshold": self.critical_threshold,
            "high_threshold":     self.high_threshold,
            "medium_threshold":   self.medium_threshold,
        }
        with open("assets/training_state.json", "w") as f:
            json.dump(state, f)
        logger.info("Training state saved with calibrated thresholds.")

    def _load_training_state(
        self,
        default: bool = False
    ) -> None:

        try:
            with open(self.training_state_path) as f:
                state = json.load(f)

            self.is_initial_training_complete = bool(
                state.get(
                    "is_initial_training_complete",
                    default
                )
            )
            self.critical_threshold = state.get("critical_threshold")
            self.high_threshold     = state.get("high_threshold")
            self.medium_threshold   = state.get("medium_threshold")

            logger.info(
                "Training State Loaded: initial_complete=%s",
                self.is_initial_training_complete
            )

        except FileNotFoundError:
            self.is_initial_training_complete = default
            logger.info(
                "No training state file; "
                "initial_complete inferred as %s",
                self.is_initial_training_complete
            )
            self._save_training_state()

        except Exception as error:
            self.is_initial_training_complete = default
            logger.warning(
                "Training State Load Failed: %s",
                error
            )
            self._save_training_state()

    def load_model(self) -> None:

        model_loaded = False

        try:
            self.model = joblib.load(self.model_path)
            self.is_trained = True
            model_loaded = True
            logger.info("ML Model Loaded")

        except FileNotFoundError:
            logger.info(
                "No model file - "
                "run with --train to build baseline."
            )

        except Exception as error:
            logger.warning(
                "Model Load Failed: %s",
                error
            )

        self._load_training_state(
            default=model_loaded
        )

        if None in (self.critical_threshold, self.high_threshold, self.medium_threshold):
            logger.warning(
                "Thresholds not calibrated - ML scoring disabled. "
                "Run py -3.10 main.py --train to calibrate for this machine."
            )
            self.is_trained = False
        else:
            logger.info(
                "Thresholds restored - CRITICAL: %.4f | HIGH: %.4f | MEDIUM: %.4f",
                self.critical_threshold,
                self.high_threshold,
                self.medium_threshold,
            )

        if os.path.exists(PARTIAL_MODEL_FLAG):
            logger.warning(
                "Loaded a partial model - still collecting full 4hr baseline - 1440 samples. "
                "Detection is active but accuracy improves as more data is collected."
            )

        event_bus.publish({
            "type":      "ML_STATUS",
            "trained":   self.is_initial_training_complete,
            "partial":   os.path.exists(PARTIAL_MODEL_FLAG),
            "timestamp": time.time(),
        })


ml_detector = MLDetector()