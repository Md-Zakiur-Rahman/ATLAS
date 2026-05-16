import time

from monitor.feature_extractor import (
    feature_extractor
)

from monitor.ml_detector import (
    ml_detector
)

print(
    "Generating baseline vectors..."
)

for _ in range(15):

    feature_extractor.build_feature_vector()

    time.sleep(1)

print(
    "Training model..."
)

ml_detector.train()

vector = (
    feature_extractor
    .build_feature_vector()
)

score = ml_detector.score(
    vector
)

severity = (
    ml_detector
    .get_severity_from_score(
        score
    )
)

print(
    f"Score: {score}"
)

print(
    f"Severity: {severity}"
)