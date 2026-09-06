import numpy as np

def calculate_cohens_kappa(detector_labels: list[int], classifier_labels: list[int]) -> float:
    """
    Calculates Cohen's Kappa (IAA) between Detector flags (Person B) 
    and Semantic Classifier flags (Person C).
    0 = Binary Safe, 1 = Binary Flagged/Threat.
    """
    detector = np.array(detector_labels)
    classifier = np.array(classifier_labels)
    
    total = len(detector)
    if total == 0 or len(classifier) != total:
        return 0.0

    # Observed agreement (Po)
    po = np.sum(detector == classifier) / total

    # Expected agreement (Pe) by chance
    p_detector_1 = np.sum(detector == 1) / total
    p_detector_0 = np.sum(detector == 0) / total
    p_class_1 = np.sum(classifier == 1) / total
    p_class_0 = np.sum(classifier == 0) / total

    pe = (p_detector_1 * p_class_1) + (p_detector_0 * p_class_0)

    if pe == 1:
        return 1.0  # Perfect agreement avoiding division by zero

    kappa = (po - pe) / (1 - pe)
    return round(float(kappa), 4)