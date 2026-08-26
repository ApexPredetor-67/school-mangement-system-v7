import base64, json
import numpy as np

try:
    import cv2
    import face_recognition
except Exception:
    cv2 = None
    face_recognition = None


def available():
    return cv2 is not None and face_recognition is not None


def decode_data_url(data_url: str):
    if not available() or not data_url or ',' not in data_url:
        raise ValueError('Face-recognition dependencies or image data are missing')
    raw = base64.b64decode(data_url.split(',',1)[1])
    arr = np.frombuffer(raw, np.uint8)
    return cv2.imdecode(arr, cv2.IMREAD_COLOR)


def encode_frame(data_url: str):
    frame = decode_data_url(data_url)
    rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    locations = face_recognition.face_locations(rgb, model='hog')
    if len(locations) != 1:
        raise ValueError('Exactly one face must be visible')
    encs = face_recognition.face_encodings(rgb, locations)
    if not encs:
        raise ValueError('Could not create a face encoding')
    return encs[0].tolist()


def best_match(probe, encodings, tolerance=0.48):
    if not encodings or not available():
        return False
    known = np.array(encodings, dtype=float)
    distances = face_recognition.face_distance(known, np.array(probe, dtype=float))
    if len(distances) == 0:
        return False
    return float(np.min(distances)) <= tolerance


def match_distance(probe, encodings):
    if not encodings or not available():
        return None
    known = np.array(encodings, dtype=float)
    distances = face_recognition.face_distance(known, np.array(probe, dtype=float))
    if len(distances) == 0:
        return None
    return float(np.min(distances))
